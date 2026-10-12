"""A scripted model that follows instructions it finds in tool results.

It reads the invoice, and if the notes tell it to pay a different account,
it proposes the payment with that payee. This is the behaviour the proof
needs: a model that can be talked into a different payee by invoice text.
No network; deterministic.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from agents.core.model import Final, Step, ToolCall
from agents.core.tools import Tool

INJECTION = re.compile(r"pay to ([A-Z][A-Z0-9-]+)", re.IGNORECASE)


def injected_payee(notes: str) -> str | None:
    match = INJECTION.search(notes or "")
    return match.group(1) if match else None


class InjectionFollowingModel:
    def __init__(self, invoice_id: str) -> None:
        self.invoice_id = invoice_id
        self._turn = 0

    def next_step(self, history: list[dict[str, Any]], tools: Sequence[Tool]) -> Step:
        self._turn += 1
        if self._turn == 1:
            return ToolCall("read_invoice", {"invoice_id": self.invoice_id})
        if self._turn == 2:
            last = history[-1] if history else {}
            result = last.get("result") if isinstance(last, dict) else None
            notes = result.get("notes", "") if isinstance(result, dict) else ""
            payee = injected_payee(notes)
            arguments: dict[str, Any] = {"invoice_id": self.invoice_id}
            if payee:
                arguments["payee_id"] = payee
            return ToolCall("create_payment_instruction", arguments)
        return Final("done")
