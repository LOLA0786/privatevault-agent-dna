"""A file-based approval inbox shared by the agent and the human approver.

The agent writes one request per REQUIRE_APPROVAL into ``pending/``: the
exact execution action PrivateVault was asked about, the request id, the
reason, and the digest of the order bytes that would be dispatched. The
approver's terminal reads it, shows it, and writes a decision into
``decided/`` carrying the signed ``approval_v01`` block (or a denial). The
agent polls for the decision. Files are written atomically; the approver's
private keys never pass through the inbox.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


@dataclass(frozen=True)
class PendingApproval:
    request_id: str
    action: dict[str, Any]
    reason: str
    wire_digest: str
    wire_length: int
    submitted_at: str
    context: dict[str, Any]

    @property
    def parameters(self) -> dict[str, Any]:
        return dict(self.action.get("parameters", {}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "reason": self.reason,
            "wire_digest": self.wire_digest,
            "wire_length": self.wire_length,
            "submitted_at": self.submitted_at,
            "context": self.context,
        }


class ApprovalInbox:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.pending_dir = self.root / "pending"
        self.decided_dir = self.root / "decided"
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.decided_dir.mkdir(parents=True, exist_ok=True)

    # ---- agent side
    def submit(
        self,
        *,
        request_id: str,
        action: dict[str, Any],
        reason: str,
        wire_digest: str,
        wire_length: int,
        context: dict[str, Any] | None = None,
    ) -> PendingApproval:
        item = PendingApproval(
            request_id=request_id,
            action=action,
            reason=reason,
            wire_digest=wire_digest,
            wire_length=wire_length,
            submitted_at=_now(),
            context=dict(context or {}),
        )
        _write_atomic(self.pending_dir / f"{request_id}.json", item.to_dict())
        return item

    def wait(
        self, request_id: str, *, timeout_s: float = 600.0, poll_s: float = 0.5
    ) -> dict[str, Any] | None:
        """Block until a decision file exists. None on timeout."""
        deadline = time.monotonic() + timeout_s
        path = self.decided_dir / f"{request_id}.json"
        while time.monotonic() < deadline:
            if path.exists():
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except ValueError:
                    time.sleep(poll_s)  # half-written; retry
                    continue
            time.sleep(poll_s)
        return None

    # ---- approver side
    def pending(self) -> list[PendingApproval]:
        items = []
        for path in sorted(self.pending_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            items.append(
                PendingApproval(
                    request_id=data["request_id"],
                    action=data["action"],
                    reason=data.get("reason", ""),
                    wire_digest=data.get("wire_digest", ""),
                    wire_length=int(data.get("wire_length", 0)),
                    submitted_at=data.get("submitted_at", ""),
                    context=data.get("context", {}),
                )
            )
        return items

    def decide(
        self,
        item: PendingApproval,
        *,
        approved: bool,
        approval: dict[str, Any] | None,
        approver: str,
    ) -> Path:
        if approved and approval is None:
            raise ValueError("an approval decision needs the signed approval block")
        payload = {
            "request_id": item.request_id,
            "decision": "approve" if approved else "deny",
            "approval": approval if approved else None,
            "approver": approver,
            "decided_at": _now(),
            "action_digest_shown": item.wire_digest,
        }
        path = self.decided_dir / f"{item.request_id}.json"
        _write_atomic(path, payload)
        pending = self.pending_dir / f"{item.request_id}.json"
        if pending.exists():
            os.replace(pending, self.decided_dir / f"{item.request_id}.request.json")
        return path
