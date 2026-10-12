"""Finance ops tools. Fixture invoices stand in for an AP system.

``create_payment_instruction`` is the money tool: it has no local effect. Its
arguments are resolved from the invoice (amount, payee, whether a purchase
order matched) so PrivateVault decides on the real numbers, and the same
arguments are the exact bytes the receiver gate gets.
"""

from __future__ import annotations

from typing import Any

from agents.core.gate import wire_for as _wire_for
from agents.core.tools import ReceiverSpec, RiskClass, Tool

PAYMENTS = ReceiverSpec(
    receiver_id="payments.partner.example",
    destination="https://payments.partner.example",
    operation="POST /api/v1/transfers",
    tool_id="payments.transfers.v1",
)

# invoice_id -> (amount INR, payee_id, matching PO or None)
INVOICES: dict[str, dict[str, Any]] = {
    "INV-1001": {"amount": 4200, "payee_id": "V-100", "po_id": "PO-77"},
    "INV-1002": {"amount": 18000, "payee_id": "V-100", "po_id": "PO-78"},
    "INV-1003": {"amount": 7000, "payee_id": "V-999", "po_id": "PO-79"},
    "INV-1004": {"amount": 60000, "payee_id": "V-200", "po_id": "PO-80"},
    "INV-1005": {"amount": 18000, "payee_id": "V-200", "po_id": "PO-81"},
    "INV-1006": {"amount": 3000, "payee_id": "V-300", "po_id": None},
}


def _invoice(args: dict[str, Any]) -> dict[str, Any]:
    invoice_id = str(args["invoice_id"])
    try:
        return {"invoice_id": invoice_id, **INVOICES[invoice_id]}
    except KeyError:
        raise ValueError(f"unknown invoice {invoice_id}") from None


def read_invoice(args: dict[str, Any]) -> dict[str, Any]:
    invoice = _invoice(args)
    return {k: invoice[k] for k in ("invoice_id", "amount", "payee_id")} | {
        "currency": "INR"
    }


def match_purchase_order(args: dict[str, Any]) -> dict[str, Any]:
    invoice = _invoice(args)
    return {
        "invoice_id": invoice["invoice_id"],
        "po_matched": invoice["po_id"] is not None,
        "po_id": invoice["po_id"],
    }


def payment_arguments(invoice_id: str | dict[str, Any]) -> dict[str, Any]:
    """The decided and dispatched arguments for a payment instruction."""
    args = {"invoice_id": invoice_id} if isinstance(invoice_id, str) else invoice_id
    invoice = _invoice(args)
    return {
        "invoice_id": invoice["invoice_id"],
        "amount": int(invoice["amount"]),
        "currency": "INR",
        "payee_id": invoice["payee_id"],
        "po_matched": invoice["po_id"] is not None,
    }


def wire_for(arguments: dict[str, Any]) -> bytes:
    return _wire_for(arguments)


def notify_ap_team(args: dict[str, Any]) -> dict[str, Any]:
    return {"notified": "ap-team"}


READ_INVOICE = Tool(
    name="read_invoice",
    description="Read an invoice: amount, currency, payee.",
    capability="ap.read_invoice",
    risk=RiskClass.READ,
    execute=read_invoice,
    parameters={"invoice_id": ("string", "invoice identifier")},
)

MATCH_PO = Tool(
    name="match_purchase_order",
    description="Check whether a purchase order matches the invoice.",
    capability="ap.match_po",
    risk=RiskClass.READ,
    execute=match_purchase_order,
    parameters={"invoice_id": ("string", "invoice identifier")},
)

PAY_TOOL = Tool(
    name="create_payment_instruction",
    description="Create a payment instruction at the payments receiver for an invoice.",
    capability="payments.pay_invoice",
    risk=RiskClass.MONEY,
    prepare=payment_arguments,
    resource=lambda args: f"vendor:{args['payee_id']}",
    receiver=PAYMENTS,
    parameters={"invoice_id": ("string", "invoice identifier")},
)

NOTIFY = Tool(
    name="notify_ap_team",
    description="Tell the AP team what happened with an invoice.",
    capability="comms.notify_ap",
    risk=RiskClass.EXTERNAL,
    execute=notify_ap_team,
    parameters={"invoice_id": ("string", "invoice identifier")},
)

TOOLS = [READ_INVOICE, MATCH_PO, PAY_TOOL, NOTIFY]
