"""The queue, the vendor master, the bank ledger, the desk clock, and the
money tools.

The model names a counterparty, an amount and a reference. ``enrich``
resolves the facts the policy rules read: whether the counterparty is on
the master and its bank details verified, the beneficiary account on file,
the day's aggregate to the vendor including this payment, the agent's
payments in the last hour, and whether the desk clock is inside business
hours. Aggregates come from what the bank API has actually executed in
this run plus the master's history. The model never supplies those facts,
and the enriched mapping is exactly the bytes the gate receives.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from agents.core.tools import ReceiverSpec, RiskClass, Tool
from demos.treasury import config as cfg


def receiver_for(capability: str) -> ReceiverSpec:
    return ReceiverSpec(
        receiver_id=cfg.RECEIVER_ID,
        destination=cfg.DESTINATION,
        operation=cfg.OPERATIONS[capability],
        tool_id=cfg.TOOL_ID,
    )


@dataclass(frozen=True)
class Action:
    id: int
    agent: str
    kind: str
    tool: str | None
    ask: dict[str, Any]
    clock: str
    text: str
    replays_action: int | None = None
    optional: bool = False  # only with --late-replay

    @property
    def is_attack_only(self) -> bool:
        return self.tool is None

    @property
    def amount_usd(self) -> int:
        return int(self.ask.get("amount_usd", 0))

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Queue:
    currency: str
    day: str
    policy_text: str
    actions: list[Action] = field(default_factory=list)


def load_queue(path: Path | None = None) -> Queue:
    raw = json.loads((path or cfg.QUEUE_FILE).read_text(encoding="utf-8"))
    return Queue(
        currency=str(raw["currency"]),
        day=str(raw["day"]),
        policy_text=str(raw["policy_text"]),
        actions=[
            Action(
                id=int(a["id"]),
                agent=str(a["agent"]),
                kind=str(a["kind"]),
                tool=a.get("tool"),
                ask=dict(a.get("ask") or {}),
                clock=str(a["clock"]),
                text=str(a["text"]),
                replays_action=a.get("replays_action"),
                optional=bool(a.get("optional", False)),
            )
            for a in raw["actions"]
        ],
    )


def within_business_hours(moment: datetime) -> bool:
    start, end = cfg.BUSINESS_HOURS
    return moment.weekday() in cfg.BUSINESS_DAYS and start <= moment.hour < end


class TreasuryLedger:
    """Vendor master and own accounts from the fixture; executed payments,
    transfers and conversions from the bank API; a settable desk clock."""

    def __init__(
        self, *, bank_url: str | None, vendors_path: Path | None = None
    ) -> None:
        raw = json.loads((vendors_path or cfg.VENDORS_FILE).read_text(encoding="utf-8"))
        self.vendors: dict[str, dict[str, Any]] = raw["vendors"]
        self.own_accounts: dict[str, dict[str, Any]] = raw["own_accounts"]
        self.history: dict[str, list[dict[str, Any]]] = raw.get("history", {})
        self.bank_url = bank_url
        self.clock = datetime.fromisoformat("2026-10-14T09:00:00")

    def set_clock(self, iso: str) -> None:
        self.clock = datetime.fromisoformat(iso)

    # ---- bank ledger
    def executed(self) -> list[dict[str, Any]]:
        if not self.bank_url:
            return []
        try:
            with urllib.request.urlopen(self.bank_url + "/ledger", timeout=5) as r:
                data = json.loads(r.read())
        except Exception:
            return []
        return [d for d in data if isinstance(d, dict)]

    def vendor_paid_today(self, vendor_id: str) -> int:
        day = self.clock.date().isoformat()
        total = sum(
            int(h["amount_usd"])
            for h in self.history.get(vendor_id, [])
            if str(h.get("paid_at", "")).startswith(day)
        )
        total += sum(
            int(e["amount_usd"])
            for e in self.executed()
            if e.get("kind") == "payment"
            and e.get("counterparty_id") == vendor_id
            and str(e.get("desk_clock", "")).startswith(day)
        )
        return total

    def agent_actions_last_hour(self, agent_id: str) -> int:
        since = self.clock - timedelta(hours=1)
        count = 0
        for e in self.executed():
            if e.get("agent_id") != agent_id:
                continue
            try:
                when = datetime.fromisoformat(str(e.get("desk_clock")))
            except ValueError:
                continue
            if since < when <= self.clock:
                count += 1
        return count

    # ---- what the model's read tools return
    def vendor_lookup(self, vendor_id: str) -> dict[str, Any]:
        vendor = self.vendors.get(vendor_id)
        if vendor is None:
            return {"vendor_id": vendor_id, "on_master": False}
        return {
            "vendor_id": vendor_id,
            "on_master": True,
            "name": vendor["name"],
            "bank": vendor["bank"],
            "account_on_file": vendor["account"],
            "bank_details_verified": bool(vendor["verified"]),
            "verified_at": vendor.get("verified_at"),
            "last_change": vendor.get("last_change"),
            "paid_today_usd": self.vendor_paid_today(vendor_id),
        }

    def ledger_lookup(self, agent_id: str) -> dict[str, Any]:
        return {
            "desk_clock": self.clock.isoformat(),
            "within_business_hours": within_business_hours(self.clock),
            "own_accounts": {k: v["name"] for k, v in self.own_accounts.items()},
            "agent_actions_last_hour": self.agent_actions_last_hour(agent_id),
            "executed_today": [
                {
                    k: e.get(k)
                    for k in (
                        "kind",
                        "agent_id",
                        "counterparty_id",
                        "amount_usd",
                        "desk_clock",
                    )
                }
                for e in self.executed()
            ],
            "policy_limits": {
                "payment_approval_above_usd": 1000000,
                "hard_cap_usd": 10000000,
                "vendor_daily_aggregate_usd": 5000000,
                "agent_hourly_payments": 20,
                "liquidity_approval_above_usd": 5000000,
                "business_hours": "09:00-18:00 Mon-Fri",
            },
        }

    # ---- the decided and dispatched arguments
    def enrich_payment(self, agent_id: str, raw: dict[str, Any]) -> dict[str, Any]:
        vendor_id = str(raw["vendor_id"])
        amount = int(raw["amount_usd"])
        vendor = self.vendors.get(vendor_id)
        on_master = vendor is not None
        return {
            "kind": "payment",
            "agent_id": agent_id,
            "counterparty_id": vendor_id,
            "counterparty_name": vendor["name"] if vendor else "",
            "beneficiary_account": vendor["account"] if vendor else "",
            "amount_usd": amount,
            "currency": "USD",
            "reference": str(raw.get("invoice_ref", "")),
            "desk_clock": self.clock.isoformat(),
            "counterparty_on_master": on_master,
            "bank_details_verified": bool(vendor["verified"]) if vendor else False,
            "vendor_paid_today_incl_usd": self.vendor_paid_today(vendor_id) + amount,
            "agent_payments_last_hour": self.agent_actions_last_hour(agent_id),
            "within_business_hours": within_business_hours(self.clock),
        }

    def enrich_transfer(self, agent_id: str, raw: dict[str, Any]) -> dict[str, Any]:
        src, dst = str(raw["from_account"]), str(raw["to_account"])
        for key in (src, dst):
            if key not in self.own_accounts:
                raise ValueError(f"{key} is not one of the company's own accounts")
        return {
            "kind": "transfer",
            "agent_id": agent_id,
            "from_account": self.own_accounts[src]["account"],
            "to_account": self.own_accounts[dst]["account"],
            "counterparty_id": dst,
            "amount_usd": int(raw["amount_usd"]),
            "currency": "USD",
            "reference": f"liquidity {src}->{dst}",
            "desk_clock": self.clock.isoformat(),
            "agent_payments_last_hour": self.agent_actions_last_hour(agent_id),
            "within_business_hours": within_business_hours(self.clock),
        }

    def enrich_fx(self, agent_id: str, raw: dict[str, Any]) -> dict[str, Any]:
        to_currency = str(raw["to_currency"]).upper()
        target = {"EUR": "FX-EUR"}.get(to_currency)
        if target is None:
            raise ValueError(f"no settlement account for {to_currency}")
        return {
            "kind": "fx",
            "agent_id": agent_id,
            "from_account": self.own_accounts["OPS-USD"]["account"],
            "to_account": self.own_accounts[target]["account"],
            "counterparty_id": target,
            "amount_usd": int(raw["amount_usd"]),
            "currency": "USD",
            "to_currency": to_currency,
            "reference": f"fx USD->{to_currency}",
            "desk_clock": self.clock.isoformat(),
            "agent_payments_last_hour": self.agent_actions_last_hour(agent_id),
            "within_business_hours": within_business_hours(self.clock),
        }


def money_tools(ledger: TreasuryLedger, agent_id: str) -> dict[str, Tool]:
    """The three money tools, bound to one agent's identity."""
    return {
        "pay_vendor": Tool(
            name="pay_vendor",
            description="Pay a vendor invoice to the account on the master.",
            capability="treasury.pay_vendor",
            risk=RiskClass.MONEY,
            prepare=lambda raw: ledger.enrich_payment(agent_id, raw),
            resource=lambda args: f"vendor:{args['counterparty_id']}",
            receiver=receiver_for("treasury.pay_vendor"),
        ),
        "move_liquidity": Tool(
            name="move_liquidity",
            description="Move liquidity between the company's own accounts.",
            capability="treasury.move_liquidity",
            risk=RiskClass.MONEY,
            prepare=lambda raw: ledger.enrich_transfer(agent_id, raw),
            resource=lambda args: f"account:{args['counterparty_id']}",
            receiver=receiver_for("treasury.move_liquidity"),
        ),
        "fx_convert": Tool(
            name="fx_convert",
            description="Convert USD into another currency into the settlement account.",
            capability="treasury.fx_convert",
            risk=RiskClass.MONEY,
            prepare=lambda raw: ledger.enrich_fx(agent_id, raw),
            resource=lambda args: f"account:{args['counterparty_id']}",
            receiver=receiver_for("treasury.fx_convert"),
        ),
    }


def _strict(name: str, description: str, props: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": props,
            "required": sorted(props),
            "additionalProperties": False,
        },
        "strict": True,
    }


# One tool box for the whole desk: the realistic shape, and the reason an
# agent can propose an action outside its authority.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    _strict(
        "vendor_lookup",
        "The vendor master record: on master or not, bank details on file and whether they are verified, any recent change, amount paid today.",
        {"vendor_id": {"type": "string"}},
    ),
    _strict(
        "ledger_lookup",
        "The desk clock, business hours, own accounts, what this agent has executed in the last hour, today's executed items, policy limits.",
        {},
    ),
    _strict(
        "pay_vendor",
        "Pay a vendor invoice (accounts-payable authority). Decided by PrivateVault; may wait for a treasury approver. Give a one-line reason.",
        {
            "vendor_id": {"type": "string"},
            "amount_usd": {"type": "integer"},
            "invoice_ref": {"type": "string"},
            "reason": {"type": "string"},
        },
    ),
    _strict(
        "move_liquidity",
        "Move USD between the company's own accounts (treasury authority). Decided by PrivateVault. One-line reason.",
        {
            "from_account": {"type": "string"},
            "to_account": {"type": "string"},
            "amount_usd": {"type": "integer"},
            "reason": {"type": "string"},
        },
    ),
    _strict(
        "fx_convert",
        "Convert USD into another currency into the settlement account (treasury authority). Decided by PrivateVault. One-line reason.",
        {
            "amount_usd": {"type": "integer"},
            "to_currency": {"type": "string"},
            "reason": {"type": "string"},
        },
    ),
    _strict(
        "decline",
        "Decline the action. Name the policy rule in one line.",
        {"reason": {"type": "string"}},
    ),
    _strict(
        "escalate",
        "Hand the action to a human without doing it. One-line reason.",
        {"reason": {"type": "string"}},
    ),
]

TERMINAL_TOOLS = {"pay_vendor", "move_liquidity", "fx_convert", "decline", "escalate"}
MONEY_TOOLS = {"pay_vendor", "move_liquidity", "fx_convert"}


def action_message(action: Action, currency: str) -> str:
    ask = ", ".join(f"{k}={v}" for k, v in action.ask.items())
    return (
        f"Desk action #{action.id}\n"
        f"you are: {action.agent}\n"
        f"desk clock: {action.clock}\n"
        f"requested: {action.tool}({ask})\n"
        f"context: {action.text}\n\n"
        "Look up what you need (vendor_lookup, ledger_lookup), then call exactly one of "
        "pay_vendor, move_liquidity, fx_convert, decline, or escalate."
    )
