"""Live browser dashboard for the treasury demo.

    make -C demos/treasury dashboard          # http://127.0.0.1:8765
    uv run python demos/treasury/dashboard.py --run runs/<ts>-naive.jsonl   # one saved run

Read-only. It tails the newest ``runs/*.jsonl`` the agent is writing (one
line per finished action, flushed as it happens), shows which queue action
Claude is working on, any approval waiting in the approver inbox, and the
three services' health. It signs nothing and moves no money: the approver
still decides in its own terminal with its own key. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # run as a script

from demos.treasury import config as cfg  # noqa: E402

HEALTH = {"privatevault": "/health", "gate": "/_health", "bank": "/_health"}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            break  # a half-written last line; the next poll picks it up
    return out


def latest_run(pinned: Path | None) -> Path | None:
    if pinned is not None:
        return pinned
    runs = sorted(cfg.RUNS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    return runs[-1] if runs else None


def pending_approvals() -> list[dict[str, Any]]:
    pending = cfg.run_dir() / "approvals" / "pending"
    decided = cfg.run_dir() / "approvals" / "decided"
    items = []
    for path in sorted(pending.glob("*.json")) if pending.is_dir() else []:
        if (decided / path.name).exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        action = data.get("action") or {}
        params = action.get("parameters") or {}
        items.append(
            {
                "request_id": data.get("request_id"),
                "reason": data.get("reason"),
                "agent": action.get("subject_key_id"),
                "action": action.get("action"),
                "amount_usd": params.get("amount_usd"),
                "counterparty": params.get("counterparty_id"),
                "submitted_at": data.get("submitted_at"),
            }
        )
    return items


def service_health() -> dict[str, bool]:
    status = {}
    for name, path in HEALTH.items():
        try:
            with urllib.request.urlopen(cfg.url(name) + path, timeout=0.4) as r:  # noqa: S310
                status[name] = r.status < 500
        except Exception:  # noqa: BLE001 - any failure means "not up"
            status[name] = False
    return status


def state(pinned: Path | None) -> dict[str, Any]:
    queue = json.loads(cfg.QUEUE_FILE.read_text(encoding="utf-8"))
    run_path = latest_run(pinned)
    records = _read_jsonl(run_path) if run_path else []
    meta = next((r for r in records if r.get("type") == "meta"), None)
    rows = [r for r in records if r.get("type") == "row"]
    summary = next((r for r in records if r.get("type") == "summary"), None)
    return {
        "run": {
            "file": run_path.name if run_path else None,
            "meta": meta,
            "rows": rows,
            "summary": summary,
        },
        "queue": [
            {
                "id": a["id"],
                "agent": a.get("agent"),
                "text": a.get("text"),
                "optional": bool(a.get("optional")),
                "kind": a.get("kind"),
            }
            for a in queue["actions"]
        ],
        "pending": pending_approvals(),
        "services": service_health() if pinned is None else {},
        "pinned": pinned is not None,
    }


def make_handler(pinned: Path | None) -> type[BaseHTTPRequestHandler]:
    page = (Path(__file__).resolve().parent / "dashboard.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # quiet terminal
            return

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.path in ("/", "/index.html"):
                self._send(200, page, "text/html; charset=utf-8")
            elif self.path == "/state":
                body = json.dumps(state(pinned), default=str).encode("utf-8")
                self._send(200, body, "application/json")
            else:
                self._send(404, b"not found", "text/plain")

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--run", type=Path, default=None, help="show one saved run")
    args = parser.parse_args(argv)
    pinned = args.run.resolve() if args.run else None
    if pinned is not None and not pinned.is_file():
        print(f"no such run file: {pinned}", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((args.host, args.port), make_handler(pinned))
    print(f"treasury dashboard on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
