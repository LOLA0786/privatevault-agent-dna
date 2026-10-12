"""The gate: every consequential action goes through PrivateVault.

``decide`` asks ``/v1/decide``. Money tools are decided as mintable (DRP 0.2:
execution action plus dispatch context); other gated tools are audit-only.
``mint`` turns a sealed ALLOW into a single-use permit via ``/v1/authorize``,
naming the approval digest when the ALLOW came from one. ``dispatch`` hands
the permit and the exact bytes to the sidecar, which verifies, consumes,
writes once, and presents the permit to the receiver gate.

The gate never evaluates policy and never holds signing keys. Placeholder
digests (``authority_receipt``, ``state_snapshot``, ``policy_bundle``,
``obligations``) are zero here; a deployment with those artifacts supplies
them.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from agent_dna.connector.adapters.exact_byte_http import (
    ExactByteContext,
    ExactByteDispatchResult,
    ExactByteHttpDispatcher,
)
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.receiver.permit_header import encode_permit_header
from agent_dna.wire_serialization_v01 import serialize_parameters_wire
from agents.core.tools import RiskClass, Tool

SERIALIZATION = "pv-json-parameters/0.1"
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


class GateError(RuntimeError):
    """PrivateVault refused the request shape itself (4xx other than a verdict)."""


@dataclass(frozen=True)
class DecisionOutcome:
    status: int
    decision: str
    triggered_by: str
    reason: str
    record: dict[str, Any] | None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def policy_id(self) -> str | None:
        return None if self.record is None else self.record.get("policy_id")

    @property
    def approval_ref(self) -> str | None:
        return None if self.record is None else self.record.get("approval_ref")


@dataclass(frozen=True)
class PermitBundle:
    authorization: dict[str, Any]
    trust_bundle: dict[str, Any]
    at_time: str
    request_id: str
    body: dict[str, Any]
    record: dict[str, Any]

    @property
    def header(self) -> str:
        return encode_permit_header(self.authorization)

    @property
    def permit_id(self) -> str:
        return str(self.authorization["execution_authorization_id"])


def wire_for(arguments: dict[str, Any]) -> bytes:
    return serialize_parameters_wire(dict(arguments), serialization=SERIALIZATION)


class PrivateVaultGate:
    def __init__(
        self,
        client: Any,
        api_key: str,
        *,
        agent_id: str,
        organisation_id: str,
        peer_identity: bytes,
        dispatcher: ExactByteHttpDispatcher | None,
    ) -> None:
        self.client = client
        self.api_key = api_key
        self.agent_id = agent_id
        self.organisation_id = organisation_id
        self.peer_identity = peer_identity
        self.dispatcher = dispatcher

    # ---------------------------------------------------------------- decide

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key}

    @staticmethod
    def new_request_id() -> str:
        return f"req-{uuid.uuid4().hex[:12]}"

    def dispatch_context(self, tool: Tool) -> dict[str, str]:
        assert tool.receiver is not None
        return {
            "adapter": "https",
            "transport": "https",
            "operation": tool.receiver.operation,
            "destination": tool.receiver.destination,
            "wire_content_type": "application/json",
            "serialization": SERIALIZATION,
        }

    def decide(
        self,
        tool: Tool,
        arguments: dict[str, Any],
        *,
        approval: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> DecisionOutcome:
        body: dict[str, Any] = {
            "agent_id": self.agent_id,
            "capability": tool.capability,
            "timestamp": time.time(),
            "arguments": dict(arguments),
            "request_id": request_id or self.new_request_id(),
        }
        if tool.risk is RiskClass.MONEY:
            body["execution_action"] = tool.execution_action(
                self.agent_id, self.organisation_id, arguments
            )
            body["dispatch_context"] = self.dispatch_context(tool)
        if approval is not None:
            body["approval"] = approval
        response = self.client.post("/v1/decide", headers=self._headers(), json=body)
        payload = response.json()
        if response.status_code not in (200, 202, 403) or "record" not in payload:
            raise GateError(f"decide refused: {response.status_code} {payload}")
        return DecisionOutcome(
            status=response.status_code,
            decision=payload["decision"],
            triggered_by=payload["triggered_by"],
            reason=payload["reason"],
            record=payload["record"],
        )

    # ------------------------------------------------------------------ mint

    def authorize_dispatch(self, tool: Tool) -> dict[str, str]:
        assert tool.receiver is not None
        return {
            "transport": "https",
            "destination": tool.receiver.destination,
            "operation": tool.receiver.operation,
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "tool_id": tool.receiver.tool_id,
            "tool_schema_digest": ZERO,
            "tool_artifact_digest": ONE,
            "credential_audience": tool.receiver.credential_audience,
            "idempotency_key_digest": ZERO,
            "retry_policy_digest": ONE,
            "serialization": SERIALIZATION,
        }

    def mint(
        self, outcome: DecisionOutcome, tool: Tool, arguments: dict[str, Any]
    ) -> PermitBundle:
        if not outcome.allowed or outcome.record is None:
            raise GateError("only a sealed ALLOW can mint")
        if tool.risk is not RiskClass.MONEY:
            raise GateError("only money tools mint permits")
        record = outcome.record
        wire = wire_for(arguments)
        request_id = f"req-mint-{record['decision_id'][:8]}"
        body: dict[str, Any] = {
            "request_id": request_id,
            "agent_id": self.agent_id,
            "organisation_id": self.organisation_id,
            "decision_id": record["decision_id"],
            "record_hash": record["record_hash"],
            "action": tool.execution_action(
                self.agent_id, self.organisation_id, arguments
            ),
            "dispatch": self.authorize_dispatch(tool),
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(self.peer_identity),
            "decision_receipt_digest": "sha256:" + record["record_hash"],
            "authority_receipt_digest": ZERO,
            "state_snapshot_digest": ZERO,
            "policy_bundle_digest": ZERO,
            "obligations_digest": ZERO,
        }
        if record.get("triggered_by") == "approval":
            body["approval_artifact_digest"] = record["approval_ref"]
        response = self.client.post("/v1/authorize", headers=self._headers(), json=body)
        if response.status_code != 200:
            raise GateError(
                f"authorize refused: {response.status_code} {response.text}"
            )
        payload = response.json()
        return PermitBundle(
            authorization=payload["authorization"],
            trust_bundle=payload["trust_bundle"],
            at_time=payload["at_time"],
            request_id=request_id,
            body=body,
            record=record,
        )

    def mint_again(self, permit: PermitBundle) -> PermitBundle:
        """Replay the mint for the same decision: byte-identical by ADR 0016."""
        response = self.client.post(
            "/v1/authorize", headers=self._headers(), json=permit.body
        )
        if response.status_code != 200:
            raise GateError(
                f"authorize replay refused: {response.status_code} {response.text}"
            )
        payload = response.json()
        return PermitBundle(
            authorization=payload["authorization"],
            trust_bundle=payload["trust_bundle"],
            at_time=payload["at_time"],
            request_id=permit.request_id,
            body=permit.body,
            record=permit.record,
        )

    # -------------------------------------------------------------- dispatch

    def dispatch(
        self, permit: PermitBundle, tool: Tool, arguments: dict[str, Any]
    ) -> ExactByteDispatchResult:
        """Hand the permit and the bytes for ``arguments`` to the sidecar.

        ``arguments`` are what the agent is about to send. If they differ from
        what was approved and minted, the sidecar refuses before any byte.
        """
        if self.dispatcher is None:
            raise GateError("no sidecar dispatcher configured")
        body = permit.body
        context = ExactByteContext(
            request_id=permit.request_id,
            observed_action=body["action"],
            observed_dispatch=body["dispatch"],
            decision_receipt_digest=body["decision_receipt_digest"],
            authority_receipt_digest=body["authority_receipt_digest"],
            # None means no approval; verify accepts it even though the
            # dataclass annotation is narrower.
            approval_artifact_digest=body.get("approval_artifact_digest"),  # type: ignore[arg-type]
            state_snapshot_digest=body["state_snapshot_digest"],
            policy_bundle_digest=body["policy_bundle_digest"],
            obligations_digest=body["obligations_digest"],
            at_time=permit.at_time,
        )
        return self.dispatcher.dispatch(
            authorization=permit.authorization,
            context=context,
            wire_bytes=wire_for(arguments),
        )
