"""Four controls, modelled as they actually work, each with its assumptions.

Every control has the same two moments: ``approve(intent)``, what it sees
when the human signs off, and ``admit(request)``, what it sees when the
request reaches the system of record. The attack lives in the gap between
the two.

a) LLM guardrail stub: a content filter over the tool-call text. Modelled
   generously: it runs at approval and, optionally, again on the outgoing
   request. It judges content, not binding: an altered amount or payee is
   still a normal payment.
b) API gateway: API-key authentication plus an OPA-style rule evaluated per
   request (``amount < cap``). Modelled with the same cap the persona policy
   uses (50,000). It knows the caller and the amount, not what was
   approved.
c) Idempotency key: the gateway deduplicates by ``Idempotency-Key``.
   Modelled in its strict form: the same key with a different body is
   rejected. The caller chooses the key, so an attacker mints a fresh one.
d) PrivateVault receiver gate: the real ``ReceiverGate`` with a permit
   minted for the approved bytes (ADR 0017, ADR 0019). Verifies that the
   bytes that arrive are the bytes that were approved.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from nacl.signing import SigningKey

from agent_dna.authority_v01 import CANONICALIZATION, encode_public_key, sha256_digest
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.wire_serialization_v01 import serialize_parameters_wire
from network.receiver_kit.config import trust_bundle
from proof.compare.attack import INTENT, PATH, Request

SERIALIZATION = "pv-json-parameters/0.1"
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
ORGANISATION = "lender.example"
AGENT = "ap-agent-01"


def mint_permit_for(
    signer: SigningKey,
    bundle: Mapping[str, Any],
    intent: Mapping[str, Any],
    *,
    receiver_id: str,
    destination: str,
    ttl_s: int = 60,
) -> dict[str, Any]:
    """A permit bound to exactly ``intent``: the payments action, its
    serialized bytes, this receiver, this operation. Same shape the API
    mints at /v1/authorize; signed locally here so the comparison has no
    moving parts beyond the gate."""
    now = datetime.now(UTC).replace(microsecond=0)
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    not_before = now - timedelta(seconds=5)
    wire = serialize_parameters_wire(dict(intent), serialization=SERIALIZATION)
    action = {
        "subject_principal": f"{AGENT}@{ORGANISATION}",
        "subject_key_id": AGENT,
        "action": "payments.pay_invoice",
        "resource": f"vendor:{intent['payee_id']}",
        "parameters": dict(intent),
    }
    dispatch = {
        "transport": "https",
        "destination": destination,
        "operation": f"POST {PATH}",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.transfers.v1",
        "tool_schema_digest": ZERO,
        "tool_artifact_digest": ONE,
        "credential_audience": receiver_id,
        "idempotency_key_digest": ZERO,
        "retry_policy_digest": ONE,
        "serialization": SERIALIZATION,
    }
    return sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": f"eauth-{uuid.uuid4()}",
            "organisation_id": ORGANISATION,
            "request_id": f"req-{uuid.uuid4().hex[:8]}",
            "issued_at": not_before.strftime(stamp),
            "not_before": not_before.strftime(stamp),
            "expires_at": (now + timedelta(seconds=ttl_s)).strftime(stamp),
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": ZERO,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": ZERO,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(
                f"tls-spki:{receiver_id}".encode()
            ),
            "dispatch": dispatch,
            "state_snapshot_digest": ZERO,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(bundle),
            "obligations_digest": ZERO,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        signer,
    )


@dataclass(frozen=True)
class Verdict:
    admitted: bool
    reason: str

    @property
    def label(self) -> str:
        return "admitted" if self.admitted else f"refused ({self.reason})"


class Control(Protocol):
    name: str

    def approve(self, intent: Mapping[str, Any]) -> None:
        """What the control sees when the human approves the intent."""

    def admit(self, request: Request) -> Verdict:
        """What the control does when the request reaches the system."""


def _digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class GuardrailStub:
    """a) A content filter. Catches what a filter catches: injection phrases,
    exfiltration phrases, card-number shapes. Cannot see that a benign
    payment differs from the benign payment that was approved."""

    name = "a) LLM guardrail stub"
    PATTERNS = (
        re.compile(r"ignore (all |the )?previous instructions", re.IGNORECASE),
        re.compile(r"\bpay me\b", re.IGNORECASE),
        re.compile(r"\battacker\b", re.IGNORECASE),
        re.compile(r"system prompt", re.IGNORECASE),
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),  # card-number shape
    )

    def __init__(self, *, rerun_on_dispatch: bool = True) -> None:
        self.rerun_on_dispatch = rerun_on_dispatch
        self._approved_text: str | None = None

    def _scan(self, text: str) -> Verdict:
        for pattern in self.PATTERNS:
            match = pattern.search(text)
            if match:
                return Verdict(False, f"content filter matched {match.group(0)!r}")
        return Verdict(True, "content filter: no prohibited content")

    def approve(self, intent: Mapping[str, Any]) -> None:
        self._approved_text = json.dumps(dict(intent), sort_keys=True)

    def admit(self, request: Request) -> Verdict:
        if not self.rerun_on_dispatch:
            return Verdict(True, "content filter ran at approval only")
        return self._scan(request.text)


class ApiGateway:
    """b) API-key auth plus a per-request policy rule ``amount < cap``."""

    name = "b) API gateway"

    def __init__(self, *, valid_keys: set[str], cap: int) -> None:
        self.valid_keys = set(valid_keys)
        self.cap = cap

    def approve(self, intent: Mapping[str, Any]) -> None:
        return None  # the gateway is not part of the approval

    def admit(self, request: Request) -> Verdict:
        if request.api_key not in self.valid_keys:
            return Verdict(False, "invalid API key")
        amount = int(request.body["amount"])
        if amount >= self.cap:
            return Verdict(False, f"policy: amount {amount:,} >= cap {self.cap:,}")
        return Verdict(
            True, f"api key valid; policy: amount {amount:,} < cap {self.cap:,}"
        )


class IdempotencyGateway:
    """c) Deduplication by Idempotency-Key, strict variant."""

    name = "c) Idempotency key"

    def __init__(self, *, valid_keys: set[str], strict: bool = True) -> None:
        self.valid_keys = set(valid_keys)
        self.strict = strict
        self._seen: dict[str, str] = {}

    def approve(self, intent: Mapping[str, Any]) -> None:
        return None

    def admit(self, request: Request) -> Verdict:
        if request.api_key not in self.valid_keys:
            return Verdict(False, "invalid API key")
        digest = _digest(request.body)
        previous = self._seen.get(request.idempotency_key)
        if previous is not None:
            if self.strict and previous != digest:
                return Verdict(False, "idempotency key reused with a different body")
            return Verdict(
                False, "duplicate idempotency key: cached response, no new effect"
            )
        self._seen[request.idempotency_key] = digest
        return Verdict(True, "new idempotency key; api key valid")


class ReceiverGateControl:
    """d) The real receiver gate. ``approve`` mints a permit bound to the
    approved bytes; ``admit`` presents it with whatever bytes arrive."""

    name = "d) PrivateVault receiver gate"
    RECEIVER_ID = "payments.partner.example"
    DESTINATION = "https://payments.partner.example"

    def __init__(self, workdir: Path | None = None) -> None:
        self.workdir = workdir or Path(tempfile.mkdtemp(prefix="pv-compare-"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.signer = SigningKey.generate()
        keys = (("ea-signer", encode_public_key(self.signer)),)
        self.bundle = trust_bundle(ORGANISATION, keys)
        self.gate = ReceiverGate(
            receiver_id=self.RECEIVER_ID,
            destinations=frozenset({self.DESTINATION}),
            trust_bundle=self.bundle,
            ledger=ReceiverLedger(self.workdir / "receiver.db"),
            receipt_signing_key=SigningKey.generate(),
            receipt_key_id="partner-receiver-01",
        )
        self._header: str | None = None

    def approve(self, intent: Mapping[str, Any]) -> None:
        permit = mint_permit_for(
            self.signer,
            self.bundle,
            intent,
            receiver_id=self.RECEIVER_ID,
            destination=self.DESTINATION,
        )
        self._header = encode_permit_header(permit)

    def admit(self, request: Request) -> Verdict:
        if self._header is None:
            return Verdict(False, "RECEIVER_PERMIT_MISSING")
        wire = serialize_parameters_wire(
            dict(request.body), serialization=SERIALIZATION
        )
        decision = self.gate.check(
            method="POST", path=PATH, headers={PERMIT_HEADER: self._header}, body=wire
        )
        if decision.admitted:
            return Verdict(
                True, "permit verified and consumed; bytes match the approval"
            )
        return Verdict(False, decision.reason_code or "REFUSED")


def build_controls(
    *, gateway_cap: int = 50000, workdir: Path | None = None
) -> list[Control]:
    from proof.compare.attack import API_KEY

    return [
        GuardrailStub(rerun_on_dispatch=True),
        ApiGateway(valid_keys={API_KEY}, cap=gateway_cap),
        IdempotencyGateway(valid_keys={API_KEY}, strict=True),
        ReceiverGateControl(workdir),
    ]


__all__ = [
    "INTENT",
    "ApiGateway",
    "Control",
    "GuardrailStub",
    "IdempotencyGateway",
    "ReceiverGateControl",
    "Verdict",
    "build_controls",
]
