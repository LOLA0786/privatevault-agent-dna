"""The refund queue, the order ledger, and the money tool.

``issue_refund`` is the money tool. The model supplies ``order_id``,
``amount`` and ``payee``; ``RefundLedger.enrich`` resolves the facts the
PrivateVault rules read (original amount and payee, whether the payee
matches, prior refunds for the order, the customer's refunds today) from
the order record and from what the payments API has actually paid in this
run. The model never supplies those facts. The enriched mapping is what
PrivateVault decides on and exactly the bytes the gate receives.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.core.tools import ReceiverSpec, RiskClass, Tool
from demos.live_checkout import config as cfg

PAYMENTS = ReceiverSpec(
    receiver_id=cfg.RECEIVER_ID,
    destination=cfg.DESTINATION,
    operation=cfg.OPERATION,
    tool_id=cfg.TOOL_ID,
)


@dataclass(frozen=True)
class RefundRequest:
    id: int
    kind: str
    order_id: str
    customer_id: str
    original_amount: int
    original_payee: str
    requested_amount: int
    requested_payee: str
    text: str
    replays_request: int | None = None

    @property
    def is_replay(self) -> bool:
        return self.kind == "replay"

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Queue:
    currency: str
    day: str
    policy_text: str
    orders: dict[str, dict[str, Any]]
    requests: list[RefundRequest] = field(default_factory=list)


def load_queue(path: Path | None = None) -> Queue:
    raw = json.loads((path or cfg.QUEUE_FILE).read_text(encoding="utf-8"))
    requests = [
        RefundRequest(
            id=int(r["id"]),
            kind=str(r["kind"]),
            order_id=str(r["order_id"]),
            customer_id=str(r["customer_id"]),
            original_amount=int(r["original_amount"]),
            original_payee=str(r["original_payee"]),
            requested_amount=int(r["requested_amount"]),
            requested_payee=str(r["requested_payee"]),
            text=str(r["text"]),
            replays_request=r.get("replays_request"),
        )
        for r in raw["requests"]
    ]
    return Queue(
        currency=str(raw["currency"]),
        day=str(raw["day"]),
        policy_text=str(raw["policy_text"]),
        orders={k: dict(v) for k, v in raw["orders"].items()},
        requests=requests,
    )


class RefundLedger:
    """Order records from the fixture plus refunds paid in this run.

    Paid refunds are read from the payments API (``GET /refunds``, an
    unprotected read through the gate), so the facts PrivateVault decides
    on reflect what actually moved, not what the agent believes.
    """

    def __init__(self, queue: Queue, *, payments_url: str | None) -> None:
        self.queue = queue
        self.payments_url = payments_url

    def paid_this_run(self) -> list[dict[str, Any]]:
        if not self.payments_url:
            return []
        try:
            with urllib.request.urlopen(self.payments_url + "/refunds", timeout=5) as r:
                data = json.loads(r.read())
        except Exception:
            return []
        return [d for d in data if isinstance(d, dict)]

    def order(self, order_id: str) -> dict[str, Any] | None:
        record = self.queue.orders.get(order_id)
        return None if record is None else dict(record)

    def refunds_for_order(self, order_id: str) -> list[dict[str, Any]]:
        record = self.order(order_id) or {}
        history = [dict(r) for r in record.get("refunds", [])]
        live = [
            {
                "refund_id": r["refund_id"],
                "amount": r["amount"],
                "payee": r["payee"],
                "paid_at": "today (this run)",
            }
            for r in self.paid_this_run()
            if r.get("order_id") == order_id
        ]
        return history + live

    def customer_refunds_today(self, customer_id: str) -> int:
        day = self.queue.day
        count = 0
        for record in self.queue.orders.values():
            if record.get("customer_id") != customer_id:
                continue
            count += sum(
                1
                for r in record.get("refunds", [])
                if str(r.get("paid_at", "")).startswith(day)
            )
        count += sum(
            1 for r in self.paid_this_run() if r.get("customer_id") == customer_id
        )
        return count

    def history(self, order_id: str) -> dict[str, Any]:
        """What the model's ``order_history`` tool returns."""
        record = self.order(order_id)
        if record is None:
            return {"error": f"no order {order_id}"}
        refunds = self.refunds_for_order(order_id)
        return {
            "order_id": order_id,
            "customer_id": record["customer_id"],
            "amount": record["amount"],
            "currency": self.queue.currency,
            "paid_with": record["paid_with"],
            "paid_at": record["paid_at"],
            "status": "refunded" if refunds else record["status"],
            "items": record["items"],
            "refunds": refunds,
            "customer_refunds_today": self.customer_refunds_today(
                record["customer_id"]
            ),
            "policy_limits": {
                "approval_above": 20000,
                "hard_cap": 200000,
                "max_refunds_per_customer_per_day": 3,
            },
        }

    def enrich(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Model arguments to the decided (and dispatched) arguments."""
        order_id = str(raw["order_id"])
        record = self.order(order_id)
        if record is None:
            raise ValueError(f"unknown order {order_id}")
        amount = int(raw["amount"])
        payee = str(raw["payee"]).strip()
        prior = self.refunds_for_order(order_id)
        return {
            "refund_id": f"RF-{order_id.removeprefix('ORD-')}-{len(prior) + 1}",
            "order_id": order_id,
            "customer_id": str(record["customer_id"]),
            "amount": amount,
            "currency": self.queue.currency,
            "payee": payee,
            "original_amount": int(record["amount"]),
            "original_payee": str(record["paid_with"]),
            "amount_exceeds_original": amount > int(record["amount"]),
            "payee_matches_original": payee == str(record["paid_with"]),
            "prior_refunds_for_order": len(prior),
            "customer_refunds_today": self.customer_refunds_today(
                str(record["customer_id"])
            ),
        }


def issue_refund_tool(ledger: RefundLedger) -> Tool:
    return Tool(
        name="issue_refund",
        description="Issue a refund for an order to a payment instrument.",
        capability="payments.issue_refund",
        risk=RiskClass.MONEY,
        prepare=ledger.enrich,
        resource=lambda args: f"order:{args['order_id']}",
        receiver=PAYMENTS,
    )


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "order_history",
        "description": "The order record: amount, payment instrument, status, refunds so far, and the customer's refunds today.",
        "input_schema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "issue_refund",
        "description": (
            "Issue the refund. Decided by PrivateVault against the refund policy; may wait "
            "for a human approval. amount is whole rupees; payee is the payment instrument "
            "to refund to. Give a one-line reason."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "integer"},
                "payee": {"type": "string"},
                "reason": {"type": "string", "description": "one line"},
            },
            "required": ["order_id", "amount", "payee", "reason"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "decline",
        "description": "Decline the request. Give the policy rule in one line.",
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "escalate",
        "description": "Hand the request to a human without issuing anything. One-line reason.",
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]

TERMINAL_TOOLS = {"issue_refund", "decline", "escalate"}


def request_message(req: RefundRequest, currency: str) -> str:
    return (
        f"Refund request #{req.id}\n"
        f"order_id: {req.order_id}\n"
        f"customer_id: {req.customer_id}\n"
        f"requested_amount: {req.requested_amount} {currency}\n"
        f"requested_payee: {req.requested_payee}\n"
        f"customer message: {req.text}\n\n"
        "Look up the order, then issue_refund, decline, or escalate."
    )
