"""Shared fixture: a core-banking transfer permit that is internally consistent
(wire bytes == pv-json-parameters serialization of action.parameters)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.wire_serialization_v01 import serialize_parameters_wire

Z = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
ORG = "lender.example"
RECEIVER = "core-banking.bank.example"
DESTINATION = "https://core-banking.bank.example:8443"
OPERATION = "POST /api/v1/accounttransfers"
METHOD, PATH = "POST", "/api/v1/accounttransfers"
SERIALIZATION = "pv-json-parameters/0.1"
PEER = b"tls-spki:core-banking.bank.example"
NOW = datetime(2026, 10, 8, 12, 0, 30, tzinfo=UTC)

PARAMETERS: dict[str, Any] = {
    "fromAccountId": "A-1001",
    "toAccountId": "B-2002",
    "transferAmount": 50000,
    "currency": "INR",
}


def wire_for(parameters: dict[str, Any]) -> bytes:
    return serialize_parameters_wire(parameters, serialization=SERIALIZATION)


def trust_bundle_for(signer: SigningKey, *, usages: list[str] | None = None) -> dict:
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-10-01T00:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(signer),
                "usages": usages or ["execution_authorization_signer"],
            }
        ],
    }


def mint(
    signer: SigningKey,
    bundle: dict,
    *,
    parameters: dict[str, Any] | None = None,
    wire: bytes | None = None,
    destination: str = DESTINATION,
    audience: str = RECEIVER,
    operation: str = OPERATION,
    not_before: str = "2026-10-08T12:00:00Z",
    expires_at: str = "2026-10-08T12:01:00Z",
    organisation_id: str = ORG,
    signer_key_id: str = "ea-signer",
    trust_bundle_digest: str | None = None,
    transport: str = "https",
    ea_id: str | None = None,
) -> dict[str, Any]:
    params = dict(PARAMETERS if parameters is None else parameters)
    body = wire_for(params) if wire is None else wire
    action = {
        "subject_principal": f"servicing-agent@{ORG}",
        "subject_key_id": "servicing-agent",
        "action": "loan.disburse_transfer",
        "resource": f"account:{params.get('fromAccountId', 'x')}",
        "parameters": params,
    }
    dispatch = {
        "transport": transport,
        "destination": destination,
        "operation": operation,
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "corebanking.accounttransfers.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": audience,
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
        "serialization": SERIALIZATION,
    }
    return sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ea_id or f"eauth-{uuid.uuid4()}",
            "organisation_id": organisation_id,
            "request_id": "req-1",
            "issued_at": not_before,
            "not_before": not_before,
            "expires_at": expires_at,
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": Z,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": Z,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(body),
            "expected_wire_bytes_length": len(body),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER),
            "dispatch": dispatch,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": trust_bundle_digest or sha256_digest(bundle),
            "obligations_digest": Z,
            "max_uses": 1,
            "signer_key_id": signer_key_id,
        },
        signer,
    )


class World:
    def __init__(self, tmp_path, **gate_kwargs: Any) -> None:
        self.signer = SigningKey.generate()
        self.bundle = trust_bundle_for(self.signer)
        self.receipt_key = SigningKey.generate()
        self.ledger_path = tmp_path / "receiver.db"
        self.ledger = ReceiverLedger(self.ledger_path)
        self.gate = ReceiverGate(
            receiver_id=RECEIVER,
            destinations=frozenset({DESTINATION}),
            trust_bundle=self.bundle,
            ledger=self.ledger,
            receipt_signing_key=self.receipt_key,
            receipt_key_id="bank-receiver-01",
            **gate_kwargs,
        )

    def permit(self, **kwargs: Any) -> dict[str, Any]:
        return mint(self.signer, self.bundle, **kwargs)

    @property
    def published_keys(self) -> dict[str, str]:
        return {"bank-receiver-01": self.gate.receipt_public_key}
