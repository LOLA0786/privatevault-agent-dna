"""Fineract enforcement cases 1–2. Cases 3–4 are not in this file."""

from __future__ import annotations

import base64
import copy
import ssl
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_dna.action_v01 import execution_action_digest
from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import (
    EXECUTION_AUTHORIZATION_CONSUMED,
    bind_authorize_to_sealed_allow,
)
from agent_dna.connector.adapters.exact_byte_http import (
    OUTCOME_CONTROL_FAILURE,
    OUTCOME_EXECUTED,
    ExactByteContext,
    ExactByteHttpDispatcher,
    TlsHttpsSidecarTransport,
    WitnessSigner,
    serialize_json_payload,
)
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_record import DRP_V02
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.grants import GrantRegistry
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tests.pilot.conftest import (
    accounttransfer_ids_for_description,
    transfer_description,
)

pytestmark = pytest.mark.pilot

_SEED_CMD = "cd pilot/fineract && python3 seed.py"
_CAP = "fineract.savings.transfer"
_AGENT = "fineract-lab-agent"
_ORG = "fineract.lab"
_Z = "sha256:" + ("0" * 64)
_ONE = "sha256:" + ("1" * 64)
_DESTINATION = "https://localhost:8443"
_OPERATION = "POST /fineract-provider/api/v1/accounttransfers"


class _StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.10,
            severity=Severity.INFO,
            reasons=[],
        )


class _InstrumentedSession:
    """Delegates to the real TLS session; counts write() only."""

    def __init__(self, inner: Any, parent: _InstrumentedTransport) -> None:
        self._inner = inner
        self._parent = parent
        self.peer_identity_bytes = inner.peer_identity_bytes

    def write(self, wire: bytes, *, operation: str):
        self._parent.write_count += 1
        return self._inner.write(wire, operation=operation)

    def close(self) -> None:
        self._inner.close()

    @property
    def closed(self) -> bool:
        return self._inner.closed


class _InstrumentedTransport(TlsHttpsSidecarTransport):
    """Real TLS transport; counts connect/write so refusals are observable."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.connect_count = 0
        self.write_count = 0

    def connect(self, destination: str, *, credential_audience: str = ""):
        self.connect_count += 1
        inner = super().connect(destination, credential_audience=credential_audience)
        return _InstrumentedSession(inner, self)


def _rfc3339_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_cert(seed_state: dict[str, Any]) -> str:
    cert = seed_state.get("cert")
    if not isinstance(cert, str) or not cert or not Path(cert).is_file():
        raise RuntimeError(
            f"seed-state.json cert path is missing or unreadable ({cert!r}). "
            f"Run: {_SEED_CMD}"
        )
    return cert


def _transfer_body(
    seed_state: dict[str, Any],
    *,
    to_account_id: int,
    request_id: str,
    transfer_amount: int,
) -> dict[str, Any]:
    """README section 4 body, filled from seed-state (not the example ids)."""
    return {
        "fromOfficeId": int(seed_state["office_id"]),
        "fromClientId": int(seed_state["client_a_id"]),
        "fromAccountType": int(seed_state["account_type_savings"]),
        "fromAccountId": int(seed_state["account_a_id"]),
        "toOfficeId": int(seed_state["office_id"]),
        "toClientId": int(seed_state["client_b_id"]),
        "toAccountType": int(seed_state["account_type_savings"]),
        "toAccountId": to_account_id,
        "dateFormat": "dd MMMM yyyy",
        "locale": "en",
        "transferDate": seed_state["business_date"],
        "transferAmount": transfer_amount,
        "transferDescription": transfer_description(request_id=request_id),
    }


def _execution_action(parameters: dict[str, Any]) -> dict[str, Any]:
    return {
        "subject_principal": f"{_AGENT}@{_ORG}",
        "subject_key_id": _AGENT,
        "action": _CAP,
        "resource": "fineract:savings:accounttransfers",
        "parameters": parameters,
    }


def _dispatch_context() -> dict[str, Any]:
    return {
        "adapter": "https",
        "transport": "https",
        "operation": _OPERATION,
        "destination": _DESTINATION,
        "wire_content_type": "application/json",
    }


def _ea_dispatch() -> dict[str, Any]:
    return {
        "transport": "https",
        "destination": _DESTINATION,
        "operation": _OPERATION,
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "fineract.accounttransfers.v1",
        "tool_schema_digest": _Z,
        "tool_artifact_digest": _ONE,
        "credential_audience": _DESTINATION,
        "idempotency_key_digest": _Z,
        "retry_policy_digest": _ONE,
    }


def _trust_bundle(runtime_key: SigningKey, witness_key: SigningKey) -> dict[str, Any]:
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": _ORG,
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": f"execution-runtime@{_ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": f"egress-witness@{_ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }


def _basic_headers(seed_state: dict[str, Any]) -> dict[str, str]:
    token = base64.b64encode(b"mifos:password").decode("ascii")
    return {
        "Authorization": f"Basic {token}",
        seed_state["tenant_header"]: seed_state["tenant_id"],
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def test_payload_mutated_after_allow(
    seed_state: dict[str, Any],
    fineract_client: Any,
    fineract_seed: Any,
    ledger_snapshot: Any,
    tmp_path: Path,
) -> None:
    if "account_type_savings" not in seed_state or "business_date" not in seed_state:
        raise RuntimeError(
            "seed-state.json is missing account_type_savings or business_date. "
            f"Run: {_SEED_CMD}"
        )
    cert_path = _require_cert(seed_state)

    counts_before = {
        name: fineract_seed.account_snapshot(fineract_client, account_id)[
            "transaction_count"
        ]
        for name, account_id in ledger_snapshot.account_ids.items()
    }

    request_id = f"req-mutated-{uuid.uuid4().hex[:12]}"
    authorized_body = _transfer_body(
        seed_state,
        to_account_id=int(seed_state["account_b_id"]),
        request_id=request_id,
        transfer_amount=500,
    )
    mutated_body = _transfer_body(
        seed_state,
        to_account_id=int(seed_state["account_c_id"]),
        request_id=request_id,
        transfer_amount=500,
    )
    assert mutated_body["toClientId"] == authorized_body["toClientId"]
    assert mutated_body["toAccountId"] != authorized_body["toAccountId"]

    authorized_action = _execution_action(authorized_body)
    mutated_action = _execution_action(mutated_body)
    dispatch_context = _dispatch_context()
    ea_dispatch = _ea_dispatch()
    authorized_wire = serialize_json_payload(authorized_body)

    registry = GrantRegistry()
    registry.grant(agent_id=_AGENT, capability=_CAP, granted_by="lab")
    engine = DecisionEngine(scorer=_StubScorer(), authorizer=registry)
    agent_action = AgentAction(
        agent_id=_AGENT,
        capability=_CAP,
        timestamp=time.time(),
        arguments=copy.deepcopy(authorized_body),
        request_id=request_id,
    )
    result = engine.decide(agent_action)
    assert result.decision is Decision.ALLOW, result.reason

    store = SQLiteDecisionStore(str(tmp_path / "pilot-consume.db"))
    recorder = DecisionRecorder(store=store)
    record = recorder.record(
        agent_action,
        result,
        execution_action=authorized_action,
        dispatch_context=dispatch_context,
    )
    assert record.protocol_version == DRP_V02
    assert record.decision == "allow"
    assert record.verify()

    sealed = record.to_dict()
    receipt = "sha256:" + record.record_hash
    bind_reason = bind_authorize_to_sealed_allow(
        sealed,
        agent_id=_AGENT,
        decision_receipt_digest=receipt,
        action=authorized_action,
        dispatch=ea_dispatch,
        record_hash=record.record_hash,
    )
    assert bind_reason is None

    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    trust_bundle = _trust_bundle(runtime_key, witness_key)
    now = _rfc3339_now()
    ea_id = f"eauth-{uuid.uuid4()}"
    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ea_id,
            "organisation_id": _ORG,
            "request_id": request_id,
            "issued_at": now,
            "not_before": now,
            "expires_at": "2099-01-01T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": receipt,
            "authority_receipt_digest": _ONE,
            "approval_artifact_digest": _Z,
            "action": authorized_action,
            "action_digest": execution_action_digest(authorized_action),
            "expected_wire_bytes_digest": sha256_bytes_digest(authorized_wire),
            "expected_wire_bytes_length": len(authorized_wire),
            "expected_peer_identity_digest": sha256_bytes_digest(
                ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text(encoding="utf-8"))
            ),
            "dispatch": ea_dispatch,
            "state_snapshot_digest": _Z,
            "policy_bundle_digest": _ONE,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": _Z,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        runtime_key,
    )

    transport = _InstrumentedTransport(
        credentials_headers=_basic_headers(seed_state),
        allowed_destinations=frozenset([_DESTINATION, "localhost"]),
        allowed_audiences=frozenset([_DESTINATION]),
        ca_file=cert_path,
        timeout_s=30.0,
        tls_verify=True,
    )
    dispatcher = ExactByteHttpDispatcher(
        consume_ledger=store,
        witness=WitnessSigner(
            signing_key=witness_key,
            signer_key_id="witness-01",
            witness_component_id="fineract-pilot-egress",
            closure_signer_key_id="witness-01",
            closure_signing_key=witness_key,
        ),
        trust_bundle=trust_bundle,
        transport=transport,
    )
    dispatch_result = dispatcher.dispatch(
        authorization=authorization,
        payload=mutated_body,
        context=ExactByteContext(
            request_id=request_id,
            observed_action=copy.deepcopy(authorized_action),
            observed_dispatch=copy.deepcopy(ea_dispatch),
            decision_receipt_digest=receipt,
            authority_receipt_digest=_ONE,
            approval_artifact_digest=_Z,
            state_snapshot_digest=_Z,
            policy_bundle_digest=_ONE,
            obligations_digest=_Z,
            at_time=_rfc3339_now(),
        ),
    )

    # 1. Connection never opened — adapter refusal, not a Fineract exception.
    assert dispatch_result.sent is False
    assert dispatch_result.outcome == OUTCOME_CONTROL_FAILURE
    assert dispatch_result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert transport.connect_count == 0
    assert dispatch_result.verification is not None
    assert (
        "authorization does not bind the intended outbound bytes"
        in dispatch_result.verification.failures
    )

    # 2. Sealed record names the authorized digest, not the mutated one.
    authorized_digest = execution_action_digest(authorized_action)
    mutated_digest = execution_action_digest(mutated_action)
    assert record.action_digest == authorized_digest
    assert record.action_digest != mutated_digest, (
        f"record.action_digest={record.action_digest} mutated={mutated_digest}"
    )

    # 3. Permit is not consumed.
    assert not store.is_execution_authorization_consumed(ea_id)

    # 4. Fineract ledger: money did not move.
    # Refetch AFTER the refusal. ledger_snapshot.before is the start-of-test
    # GET; after_snaps is a new GET, not that stored dict reused as "after".
    after_snaps = {
        name: fineract_seed.account_snapshot(fineract_client, account_id)
        for name, account_id in ledger_snapshot.account_ids.items()
    }
    for name in ("A", "B", "C"):
        before_bal = ledger_snapshot.before[name]
        after_bal = Decimal(str(after_snaps[name]["accountBalance"]))
        after_count = after_snaps[name]["transaction_count"]
        print(
            f"assertion-4 {name}: balance before={before_bal} after={after_bal} "
            f"tx_count before={counts_before[name]} after={after_count}"
        )
        assert after_bal - before_bal == Decimal("0"), (
            f"{name} balance moved: before={before_bal} after={after_bal}"
        )
        assert after_count == counts_before[name], (
            f"{name} transaction_count changed {counts_before[name]} -> {after_count}"
        )


def _mint_kit(
    seed_state: dict[str, Any],
    tmp_path: Path,
    *,
    request_id: str,
    body: dict[str, Any],
    cert_path: str,
) -> dict[str, Any]:
    action = _execution_action(body)
    ea_dispatch = _ea_dispatch()
    wire = serialize_json_payload(body)
    registry = GrantRegistry()
    registry.grant(agent_id=_AGENT, capability=_CAP, granted_by="lab")
    engine = DecisionEngine(scorer=_StubScorer(), authorizer=registry)
    agent_action = AgentAction(
        agent_id=_AGENT,
        capability=_CAP,
        timestamp=time.time(),
        arguments=copy.deepcopy(body),
        request_id=request_id,
    )
    decided = engine.decide(agent_action)
    assert decided.decision is Decision.ALLOW, decided.reason
    store = SQLiteDecisionStore(str(tmp_path / f"pilot-consume-{request_id}.db"))
    record = DecisionRecorder(store=store).record(
        agent_action,
        decided,
        execution_action=action,
        dispatch_context=_dispatch_context(),
    )
    assert record.protocol_version == DRP_V02
    assert record.verify()
    receipt = "sha256:" + record.record_hash
    bind_reason = bind_authorize_to_sealed_allow(
        record.to_dict(),
        agent_id=_AGENT,
        decision_receipt_digest=receipt,
        action=action,
        dispatch=ea_dispatch,
        record_hash=record.record_hash,
    )
    assert bind_reason is None
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    trust_bundle = _trust_bundle(runtime_key, witness_key)
    now = _rfc3339_now()
    ea_id = f"eauth-{uuid.uuid4()}"
    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ea_id,
            "organisation_id": _ORG,
            "request_id": request_id,
            "issued_at": now,
            "not_before": now,
            "expires_at": "2099-01-01T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": receipt,
            "authority_receipt_digest": _ONE,
            "approval_artifact_digest": _Z,
            "action": action,
            "action_digest": execution_action_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(
                ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text(encoding="utf-8"))
            ),
            "dispatch": ea_dispatch,
            "state_snapshot_digest": _Z,
            "policy_bundle_digest": _ONE,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": _Z,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        runtime_key,
    )
    transport = _InstrumentedTransport(
        credentials_headers=_basic_headers(seed_state),
        allowed_destinations=frozenset([_DESTINATION, "localhost"]),
        allowed_audiences=frozenset([_DESTINATION]),
        ca_file=cert_path,
        timeout_s=30.0,
        tls_verify=True,
    )
    dispatcher = ExactByteHttpDispatcher(
        consume_ledger=store,
        witness=WitnessSigner(
            signing_key=witness_key,
            signer_key_id="witness-01",
            witness_component_id="fineract-pilot-egress",
            closure_signer_key_id="witness-01",
            closure_signing_key=witness_key,
        ),
        trust_bundle=trust_bundle,
        transport=transport,
    )
    context = ExactByteContext(
        request_id=request_id,
        observed_action=copy.deepcopy(action),
        observed_dispatch=copy.deepcopy(ea_dispatch),
        decision_receipt_digest=receipt,
        authority_receipt_digest=_ONE,
        approval_artifact_digest=_Z,
        state_snapshot_digest=_Z,
        policy_bundle_digest=_ONE,
        obligations_digest=_Z,
        at_time=_rfc3339_now(),
    )
    return {
        "authorization": authorization,
        "dispatcher": dispatcher,
        "transport": transport,
        "store": store,
        "ea_id": ea_id,
        "context": context,
        "description": body["transferDescription"],
    }


def _refetch(fineract_seed: Any, fineract_client: Any, ledger_snapshot: Any):
    return {
        name: fineract_seed.account_snapshot(fineract_client, account_id)
        for name, account_id in ledger_snapshot.account_ids.items()
    }


def test_permit_replay(
    seed_state: dict[str, Any],
    fineract_client: Any,
    fineract_seed: Any,
    ledger_snapshot: Any,
    tmp_path: Path,
) -> None:
    if "account_type_savings" not in seed_state or "business_date" not in seed_state:
        raise RuntimeError(
            "seed-state.json is missing account_type_savings or business_date. "
            f"Run: {_SEED_CMD}"
        )
    cert_path = _require_cert(seed_state)
    request_id = f"req-replay-{uuid.uuid4().hex[:12]}"
    body = _transfer_body(
        seed_state,
        to_account_id=int(seed_state["account_b_id"]),
        request_id=request_id,
        transfer_amount=100,
    )
    kit = _mint_kit(
        seed_state,
        tmp_path,
        request_id=request_id,
        body=body,
        cert_path=cert_path,
    )
    dispatcher = kit["dispatcher"]
    transport = kit["transport"]
    store = kit["store"]
    ea_id = kit["ea_id"]

    first = dispatcher.dispatch(
        authorization=kit["authorization"],
        payload=body,
        context=kit["context"],
    )
    assert first.outcome == OUTCOME_EXECUTED, (
        f"first dispatch must succeed: outcome={first.outcome} "
        f"reason={first.reason_code} detail={first.detail}"
    )
    assert first.sent is True
    assert first.tool_executed is True
    assert first.closure is not None
    assert first.closure["response_status"] == "200"
    assert transport.write_count == 1
    assert store.is_execution_authorization_consumed(ea_id)

    after_first = _refetch(fineract_seed, fineract_client, ledger_snapshot)
    delta_first = {
        name: Decimal(str(after_first[name]["accountBalance"]))
        - ledger_snapshot.before[name]
        for name in ("A", "B", "C")
    }
    assert delta_first["A"] == Decimal("-100"), delta_first
    assert delta_first["B"] == Decimal("100"), delta_first
    assert delta_first["C"] == Decimal("0"), delta_first
    listed = fineract_client.request("GET", f"{fineract_seed.BASE}/accounttransfers")
    first_ids = accounttransfer_ids_for_description(listed, kit["description"])
    assert len(first_ids) == 1, first_ids

    second = dispatcher.dispatch(
        authorization=kit["authorization"],
        payload=body,
        context=kit["context"],
    )
    assert second.sent is False
    assert second.outcome == OUTCOME_CONTROL_FAILURE
    assert second.reason_code == EXECUTION_AUTHORIZATION_CONSUMED
    assert transport.write_count == 1

    after_replay = _refetch(fineract_seed, fineract_client, ledger_snapshot)
    delta_replay = {
        name: Decimal(str(after_replay[name]["accountBalance"]))
        - ledger_snapshot.before[name]
        for name in ("A", "B", "C")
    }
    assert delta_replay == delta_first
    listed_again = fineract_client.request(
        "GET", f"{fineract_seed.BASE}/accounttransfers"
    )
    replay_ids = accounttransfer_ids_for_description(listed_again, kit["description"])
    assert replay_ids == first_ids
    for name in ("A", "B", "C"):
        assert (
            after_replay[name]["transaction_count"]
            == after_first[name]["transaction_count"]
        )
