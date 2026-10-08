"""Receiver-side enforcement: the system of record refuses unpermitted actions.

See ``agent_dna/receiver/gate.py`` and ``docs/adr/0019-receiver-gate.md``.
"""

from agent_dna.receiver.asgi import ReceiverGateMiddleware, ReceiverGateProxy
from agent_dna.receiver.gate import ReceiverDecision, ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import (
    PERMIT_HEADER,
    decode_permit_header,
    encode_permit_header,
)
from agent_dna.receiver.receipts import (
    RECEIVER_RECEIPT_SPEC,
    verify_receiver_receipt_chain,
)

__all__ = [
    "PERMIT_HEADER",
    "RECEIVER_RECEIPT_SPEC",
    "ReceiverDecision",
    "ReceiverGate",
    "ReceiverGateMiddleware",
    "ReceiverGateProxy",
    "ReceiverLedger",
    "decode_permit_header",
    "encode_permit_header",
    "verify_receiver_receipt_chain",
]
