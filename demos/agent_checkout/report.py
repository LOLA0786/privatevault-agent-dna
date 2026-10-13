"""Render one self-contained ``report.html`` from a scenario run.

Input is the run's own evidence: ``timeline.json`` (what each step saw at
every boundary) and the exported receiver receipts. Output is a single HTML
file with inline CSS, no scripts, no external resources, that reads the same
on a projector in light or dark mode.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from demos.agent_checkout.scenario import ScenarioResult

GOOD = "#0ca30c"
CRITICAL = "#d03b3b"
WARNING = "#fab219"
ACCENT_LIGHT = "#2a78d6"
ACCENT_DARK = "#3987e5"

CSS = f"""
:root {{
  color-scheme: light dark;
  --surface: #fcfcfb; --card: #ffffff; --line: #e2e1dc;
  --ink: #0b0b0b; --ink-2: #52514e; --ink-3: #7b7a76;
  --accent: {ACCENT_LIGHT};
  --good: {GOOD}; --critical: {CRITICAL}; --warning: {WARNING};
  --good-bg: #e8f7e8; --critical-bg: #fbe9e9; --warning-bg: #fff6df; --accent-bg: #e9f1fb;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --surface: #1a1a19; --card: #232322; --line: #3a3a38;
    --ink: #f0efec; --ink-2: #c3c2b7; --ink-3: #8e8d86;
    --accent: {ACCENT_DARK};
    --good-bg: #16331a; --critical-bg: #3b1c1c; --warning-bg: #3a2f10; --accent-bg: #1b2a3f;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--surface); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
main {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }}
h1 {{ font-size: 28px; margin: 0 0 4px; letter-spacing: -0.01em; }}
h2 {{ font-size: 18px; margin: 40px 0 12px; }}
.sub {{ color: var(--ink-2); margin: 0 0 20px; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 24px;
  font-size: 13px; color: var(--ink-2); margin-bottom: 24px; }}
.meta b {{ color: var(--ink); font-weight: 600; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }}
.tile {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }}
.tile .n {{ font-size: 30px; font-weight: 650; line-height: 1.1; }}
.tile .l {{ font-size: 13px; color: var(--ink-2); margin-top: 4px; }}
.tile.good .n {{ color: var(--good); }} .tile.critical .n {{ color: var(--critical); }}
.timeline {{ position: relative; margin: 0; padding: 0; list-style: none; }}
.timeline::before {{ content: ""; position: absolute; left: 19px; top: 8px; bottom: 8px; width: 2px; background: var(--line); }}
.ev {{ position: relative; padding: 0 0 20px 56px; }}
.ev .dot {{ position: absolute; left: 8px; top: 6px; width: 24px; height: 24px; border-radius: 50%;
  background: var(--card); border: 2px solid var(--line); display: grid; place-items: center;
  font-size: 12px; font-weight: 700; color: var(--ink-2); }}
.ev.good .dot {{ border-color: var(--good); color: var(--good); }}
.ev.critical .dot {{ border-color: var(--critical); color: var(--critical); }}
.card {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; }}
.card h3 {{ margin: 0 0 6px; font-size: 16px; }}
.card p {{ margin: 0 0 12px; color: var(--ink-2); }}
.badges {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
.badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 600; border: 1px solid transparent; }}
.badge.good {{ background: var(--good-bg); color: var(--good); border-color: var(--good); }}
.badge.critical {{ background: var(--critical-bg); color: var(--critical); border-color: var(--critical); }}
.badge.warning {{ background: var(--warning-bg); color: #7a5300; border-color: var(--warning); }}
@media (prefers-color-scheme: dark) {{ .badge.warning {{ color: var(--warning); }} }}
.badge.accent {{ background: var(--accent-bg); color: var(--accent); border-color: var(--accent); }}
.kv {{ display: grid; grid-template-columns: 150px 1fr; gap: 4px 12px; font-size: 13px; }}
.kv dt {{ color: var(--ink-3); margin: 0; }}
.kv dd {{ margin: 0; font-family: var(--mono); font-size: 12.5px; word-break: break-all; }}
.kv dd.text {{ font-family: inherit; font-size: 13px; }}
.checks {{ margin: 12px 0 0; padding: 0; list-style: none; font-size: 13px; }}
.checks li {{ padding-left: 22px; position: relative; }}
.checks li::before {{ position: absolute; left: 0; font-weight: 700; }}
.checks li.ok::before {{ content: "\\2713"; color: var(--good); }}
.checks li.bad::before {{ content: "\\2717"; color: var(--critical); }}
.note {{ background: var(--warning-bg); border-left: 3px solid var(--warning); padding: 8px 12px;
  font-size: 13px; margin: 0 0 12px; border-radius: 4px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; background: var(--card);
  border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }}
th, td {{ text-align: left; padding: 10px 12px; border-top: 1px solid var(--line); vertical-align: top; }}
th {{ border-top: 0; color: var(--ink-2); font-weight: 600; font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.04em; }}
td.mono {{ font-family: var(--mono); font-size: 12px; word-break: break-all; }}
td.through {{ color: var(--critical); font-weight: 600; }}
td.refused {{ color: var(--good); font-weight: 600; }}
code, pre {{ font-family: var(--mono); font-size: 12.5px; }}
pre {{ background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; overflow-x: auto; }}
.footer {{ color: var(--ink-3); font-size: 12.5px; margin-top: 40px; }}
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _inr(amount: Any) -> str:
    """Indian grouping: 2,50,000."""
    try:
        n = int(amount)
    except (TypeError, ValueError):
        return _e(amount)
    s = str(abs(n))
    if len(s) <= 3:
        head, tail = "", s
    else:
        head, tail = s[:-3], s[-3:]
        parts: list[str] = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        head = ",".join(parts)
    body = f"{head},{tail}" if head else tail
    return ("-" if n < 0 else "") + "₹" + body


def _short(digest: str | None, keep: int = 18) -> str:
    if not digest:
        return "—"
    text = str(digest)
    return text if len(text) <= keep + 3 else text[:keep] + "…"


def _badge(kind: str, icon: str, text: str) -> str:
    return f'<span class="badge {kind}">{icon} {_e(text)}</span>'


def _badges(ev: dict[str, Any]) -> str:
    out: list[str] = []
    decision = ev.get("decision")
    if ev.get("first_decision") and ev["first_decision"] != decision:
        out.append(_badge("warning", "○", f"decide: {ev['first_decision']}"))
    if decision == "allow":
        out.append(_badge("good", "✓", f"decide: ALLOW via {ev.get('triggered_by')}"))
    elif decision == "block":
        out.append(_badge("critical", "✗", f"decide: BLOCK ({ev.get('policy_id')})"))
    elif decision:
        out.append(_badge("warning", "○", f"decide: {decision}"))
    if ev.get("sidecar_outcome") == "EXECUTED":
        out.append(_badge("good", "✓", "sidecar: dispatched"))
    elif ev.get("sidecar_outcome"):
        out.append(
            _badge("critical", "✗", f"sidecar: refused, {ev.get('sidecar_reason')}")
        )
    status = ev.get("gate_status")
    if status is not None:
        if ev.get("gate_reason"):
            out.append(
                _badge("critical", "✗", f"gate: HTTP {status} {ev['gate_reason']}")
            )
        else:
            out.append(_badge("good", "✓", f"gate: admitted, HTTP {status}"))
    if ev.get("kind") == "evidence" and ev.get("ok"):
        out.append(_badge("good", "✓", "verified"))
    return "".join(out)


def _request_text(request: dict[str, Any] | None) -> str:
    if not request:
        return "—"
    amount = _inr(request.get("amount"))
    return (
        f"{_e(request.get('order_id'))} · {amount} {_e(request.get('currency'))}"
        f" → {_e(request.get('merchant_id'))}"
    )


def _event_card(ev: dict[str, Any]) -> str:  # noqa: C901 - one row per field
    status_class = "good" if ev["ok"] else "critical"
    if ev["kind"] == "attack" and ev["ok"]:
        status_class = "critical"  # the attack was refused: red dot, that is the point
    rows: list[str] = []

    def row(label: str, value: str, text: bool = False) -> None:
        cls = ' class="text"' if text else ""
        rows.append(f"<dt>{_e(label)}</dt><dd{cls}>{value}</dd>")

    if ev.get("request"):
        row("request", _request_text(ev["request"]), text=True)
    if ev.get("decision"):
        row("decision id", _e(ev.get("decision_id")))
    if ev.get("approval_digest"):
        row("approval", f"{_e(ev.get('approver'))}<br>{_e(ev['approval_digest'])}")
    if ev.get("permit_id"):
        row("permit id", _e(ev["permit_id"]))
    bound = ev.get("permit_bound_to")
    if bound:
        row(
            "permit bound to",
            f"bytes {_e(bound.get('wire_bytes_digest'))} ({_e(bound.get('wire_bytes_length'))} bytes)<br>"
            f"action {_e(bound.get('action_digest'))}<br>"
            f"{_e(bound.get('operation'))} at {_e(bound.get('destination'))}",
        )
    if ev.get("gate_status") is not None:
        gate = f"HTTP {ev['gate_status']}"
        if ev.get("gate_reason"):
            gate += f" {ev['gate_reason']}"
        row("gate result", _e(gate))
    if ev.get("receipt_digest"):
        seq = ev.get("receipt_sequence")
        row("receipt hash", f"#{_e(seq)} {_e(ev['receipt_digest'])}")
    if ev.get("api_response"):
        api = ev["api_response"]
        row(
            "checkout api",
            f"HTTP 201 {_e(api.get('status'))}, {_e(api.get('gateway_ref'))}",
        )
    elif ev.get("api_orders_after") is not None and ev["kind"] in ("attack", "policy"):
        row(
            "checkout api",
            f"not reached, orders still {_e(ev['api_orders_after'])}",
            text=True,
        )
    detail = ev.get("detail") or {}
    if "with_approval_decision" in detail:
        row(
            "with approval",
            f"decide again with a signed approval: {_e(detail['with_approval_decision'])}"
            f" (HTTP {_e(detail.get('with_approval_status'))})",
            text=True,
        )
    if "verifier" in detail:
        row("verifier", _e(detail["verifier"]))
        row(
            "gate key",
            f"{_e(detail.get('receiver_key_id'))} = {_e(detail.get('receiver_public_key'))}",
        )

    note = ""
    if detail.get("injected_note"):
        note = f'<div class="note"><b>Injected text on the merchant page:</b> “{_e(detail["injected_note"])}”</div>'

    checks = "".join(
        f'<li class="{"ok" if c["ok"] else "bad"}">{_e(c["label"])}</li>'
        for c in ev["checks"]
    )
    return (
        f'<li class="ev {status_class}"><div class="dot">{ev["number"]}</div>'
        f'<div class="card"><h3>{_e(ev["title"])}</h3><p>{_e(ev["narrative"])}</p>'
        f'{note}<div class="badges">{_badges(ev)}</div>'
        f'<dl class="kv">{"".join(rows)}</dl>'
        f'<ul class="checks">{checks}</ul></div></li>'
    )


def _comparison_table(rows: list[dict[str, Any]]) -> str:
    body = []
    for r in rows:
        honest = r["attack"].startswith("Honest")
        # "refused" styles the intended outcome green; "through" styles an
        # attack that became an order red. The honest order is intended on
        # both sides.
        bad_left = r["without_pv_ok"] and not honest
        good_right = honest or r["with_pv_refused"]
        left_cls = "through" if bad_left else "refused"
        right_cls = "refused" if good_right else "through"
        left_icon = "✗ " if bad_left else "✓ "
        right_icon = "✓ " if good_right else "✗ "
        body.append(
            f"<tr><td>{_e(r['attack'])}</td>"
            f'<td class="{left_cls}">{left_icon}{_e(r["without_pv"])}</td>'
            f'<td class="{right_cls}">{right_icon}{_e(r["with_pv"])}</td></tr>'
        )
    return (
        "<table><thead><tr><th>Request</th><th>Without PrivateVault</th>"
        "<th>With PrivateVault</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _orders_table(orders: list[dict[str, Any]]) -> str:
    if not orders:
        return "<p class='sub'>No orders.</p>"
    body = "".join(
        f"<tr><td class='mono'>{_e(o.get('order_id'))}</td><td>{_inr(o.get('amount'))} {_e(o.get('currency'))}</td>"
        f"<td>{_e(o.get('merchant_id'))}</td><td class='mono'>{_e(o.get('gateway_ref'))}</td></tr>"
        for o in orders
    )
    return (
        "<table><thead><tr><th>Order id</th><th>Amount</th><th>Merchant</th><th>Gateway ref</th>"
        f"</tr></thead><tbody>{body}</tbody></table>"
    )


def _receipts_table(receipts: list[dict[str, Any]]) -> str:
    body = []
    for r in receipts:
        admitted = r.get("outcome") == "ADMITTED"
        cls = "refused" if admitted else "through"
        icon = "✓ " if admitted else "✗ "
        body.append(
            f"<tr><td>{_e(r.get('sequence'))}</td>"
            f'<td class="{cls}">{icon}{_e(r.get("outcome"))}</td>'
            f"<td class='mono'>{_e(r.get('reason_code') or '')}</td>"
            f"<td class='mono'>{_e(_short(r.get('execution_authorization_id'), 20))}</td>"
            f"<td class='mono'>{_e(_short(r.get('wire_bytes_digest'), 22))} ({_e(r.get('wire_bytes_length'))} B)</td>"
            f"<td class='mono'>{_e(r.get('received_at'))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>#</th><th>Outcome</th><th>Reason</th><th>Permit</th>"
        "<th>Wire bytes</th><th>Received</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def render(result: ScenarioResult, receipts: list[dict[str, Any]]) -> str:
    data = result.to_dict()
    events = data["events"]
    attacks = [e for e in events if e["kind"] == "attack"]
    refused = sum(1 for e in attacks if e["ok"])
    blocked = sum(1 for e in events if e["kind"] == "policy" and e["ok"])
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    verdict = "ALL CHECKS PASS" if data["ok"] else "SOME CHECKS FAILED"
    verdict_cls = "good" if data["ok"] else "critical"
    policy = data["policy"]
    verify_cmd = (
        "uv run python tools/verify_receiver_receipts.py \\\n"
        f"  --jsonl {_e(result.receipts_path.name)} \\\n"
        f"  --receiver-id {_e(result.receiver_id)} \\\n"
        f"  --receiver-key {_e(result.receiver_key_id)}={_e(result.receiver_public_key)}"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent checkout with PrivateVault: run report</title>
<style>{CSS}</style></head>
<body><main>
<h1>Agent checkout, one order and four attacks</h1>
<p class="sub">A procurement agent creates a payment-gateway order through PrivateVault. One order is created once.
Every change after approval, every replay, and every request over the hard cap is refused before the order API sees it.</p>
<div class="meta">
  <div><b>Generated</b> {generated}</div>
  <div><b>Agent</b> {_e(data["agent_id"])} @ {_e(data["organisation_id"])}</div>
  <div><b>Approver</b> {_e(data["approver"])}</div>
  <div><b>Receiver gate</b> {_e(data["receiver_id"])}</div>
  <div><b>Gate receipt key</b> {_e(data["receiver_key_id"])}</div>
  <div><b>Policy</b> approval above {_inr(policy.get("approval_threshold"))}, hard cap {_inr(policy.get("hard_cap"))}</div>
  <div><b>Run directory</b> <code>{_e(data["run_dir"])}</code></div>
</div>
<div class="tiles">
  <div class="tile good"><div class="n">{len(data["orders_created"])}</div><div class="l">order created at the checkout API</div></div>
  <div class="tile critical"><div class="n">{refused}/{len(attacks)}</div><div class="l">post-approval attacks refused at the gate</div></div>
  <div class="tile critical"><div class="n">{blocked}</div><div class="l">over-cap request blocked at decide</div></div>
  <div class="tile good"><div class="n">{data["receipts_count"]}</div><div class="l">gate receipts, chain and signatures verified</div></div>
  <div class="tile {verdict_cls}"><div class="n">{"✓" if data["ok"] else "✗"}</div><div class="l">{verdict}</div></div>
</div>

<h2>Timeline</h2>
<ul class="timeline">{"".join(_event_card(e) for e in events)}</ul>

<h2>Side by side</h2>
<p class="sub">Same five requests. Left: the agent holds a valid API key and talks to the order API directly.
Right: the receiver gate sits in front of the same API and only admits bytes a single-use permit was minted for.</p>
{_comparison_table(data["comparison"])}

<h2>Orders the checkout API actually created (with PrivateVault)</h2>
{_orders_table(data["orders_created"])}

<h2>Gate receipts</h2>
<p class="sub">One signed receipt per admit and per refusal, hash-chained. Exported from the gate's ledger and verified by
<code>tools/verify_receiver_receipts.py</code>, which does not import PrivateVault. Verifier output: <code>{_e(data["verifier_output"])}</code></p>
{_receipts_table(receipts)}
<p class="sub">Re-verify from the run directory:</p>
<pre>{verify_cmd}</pre>

<h2>What this run does not show</h2>
<ul>
  <li>The agent's model is scripted so the run is reproducible; the injection is text in a fixture. A live model proposing the same change is refused the same way, because the refusal does not depend on the model.</li>
  <li>The checkout API is a mock with a real order shape. It does not authenticate or dedupe; it stands in for an upstream that trusts whatever its caller may send.</li>
  <li>The sidecar-to-gate transport is in process. The production transport derives peer identity from the TLS handshake.</li>
  <li>Keys are generated per run. A deployment pins the trust bundle and the approver bundle and keeps private keys with their owners.</li>
</ul>
<p class="footer">PrivateVault agent checkout demo. Source: <code>demos/agent_checkout/</code>. Integration options: <code>demos/agent_checkout/INTEGRATION.md</code>.</p>
</main></body></html>
"""


def load_receipts(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_report(result: ScenarioResult, out: Path) -> Path:
    receipts = load_receipts(result.receipts_path)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(result, receipts), encoding="utf-8")
    return out
