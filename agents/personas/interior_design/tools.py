"""Interior design tools. Fixture projects and purchase orders stand in for
the studio's project system.

``issue_vendor_po`` is the money tool: no local effect; its arguments are
resolved from the PO (vendor, amount, item) so PrivateVault decides on the
real numbers and the same bytes reach the vendor network's gate.
"""

from __future__ import annotations

from typing import Any

from agents.core.gate import wire_for as _wire_for
from agents.core.tools import ReceiverSpec, RiskClass, Tool

VENDOR_NETWORK = ReceiverSpec(
    receiver_id="procurement.vendor-network.example",
    destination="https://procurement.vendor-network.example",
    operation="POST /api/v1/purchase-orders",
    tool_id="procurement.purchase_orders.v1",
)

PROJECTS: dict[str, dict[str, Any]] = {
    "PRJ-1": {"client": "Mehta residence", "scope": "living room", "quote": 480000},
    "PRJ-2": {"client": "Rao office", "scope": "reception", "quote": 950000},
}

# po_id -> project, vendor, amount INR, item
PURCHASE_ORDERS: dict[str, dict[str, Any]] = {
    "PO-201": {
        "project_id": "PRJ-1",
        "vendor_id": "VN-10",
        "amount": 32000,
        "item": "fabric",
    },
    "PO-202": {
        "project_id": "PRJ-1",
        "vendor_id": "VN-20",
        "amount": 120000,
        "item": "sofa set",
    },
    "PO-203": {
        "project_id": "PRJ-2",
        "vendor_id": "VN-10",
        "amount": 250000,
        "item": "marble",
    },
    "PO-204": {
        "project_id": "PRJ-2",
        "vendor_id": "VN-99",
        "amount": 40000,
        "item": "lighting",
    },
}


def _project(args: dict[str, Any]) -> dict[str, Any]:
    project_id = str(args["project_id"])
    try:
        return {"project_id": project_id, **PROJECTS[project_id]}
    except KeyError:
        raise ValueError(f"unknown project {project_id}") from None


def read_project_brief(args: dict[str, Any]) -> dict[str, Any]:
    return _project(args)


def send_quote(args: dict[str, Any]) -> dict[str, Any]:
    project = _project(args)
    return {
        "quote_sent": True,
        "project_id": project["project_id"],
        "amount": project["quote"],
    }


def po_arguments(po_id: str | dict[str, Any]) -> dict[str, Any]:
    """The decided and dispatched arguments for a purchase order."""
    args = {"po_id": po_id} if isinstance(po_id, str) else po_id
    key = str(args["po_id"])
    try:
        po = PURCHASE_ORDERS[key]
    except KeyError:
        raise ValueError(f"unknown purchase order {key}") from None
    return {
        "po_id": key,
        "project_id": po["project_id"],
        "vendor_id": po["vendor_id"],
        "amount": int(po["amount"]),
        "currency": "INR",
        "item": po["item"],
    }


def wire_for(arguments: dict[str, Any]) -> bytes:
    return _wire_for(arguments)


def notify_client(args: dict[str, Any]) -> dict[str, Any]:
    return {"notified": _project(args)["client"]}


READ_BRIEF = Tool(
    name="read_project_brief",
    description="Read a project brief: client, scope, quoted amount.",
    capability="projects.read_brief",
    risk=RiskClass.READ,
    execute=read_project_brief,
    parameters={"project_id": ("string", "project identifier")},
)

SEND_QUOTE = Tool(
    name="send_quote",
    description="Send the client the quote for a project.",
    capability="quotes.send",
    risk=RiskClass.EXTERNAL,
    execute=send_quote,
    parameters={"project_id": ("string", "project identifier")},
)

PO_TOOL = Tool(
    name="issue_vendor_po",
    description="Issue a purchase order to a vendor through the procurement network.",
    capability="procurement.issue_po",
    risk=RiskClass.MONEY,
    prepare=po_arguments,
    resource=lambda args: f"vendor:{args['vendor_id']}",
    receiver=VENDOR_NETWORK,
    parameters={"po_id": ("string", "purchase order identifier")},
)

NOTIFY = Tool(
    name="notify_client",
    description="Tell the client where the project stands.",
    capability="comms.notify_client",
    risk=RiskClass.EXTERNAL,
    execute=notify_client,
    parameters={"project_id": ("string", "project identifier")},
)

TOOLS = [READ_BRIEF, SEND_QUOTE, PO_TOOL, NOTIFY]
