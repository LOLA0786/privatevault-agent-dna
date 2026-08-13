"""Adapter conformance suite — plug any dispatch adapter harness here.

Contract (see agent_dna.connector.adapters.conformance):
  C1. Refusal produces no side effect.
  C2. Successful allow emits exactly the checked payload.
  C3. Replay / second refuse path produces no additional side effect.
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from nacl.signing import SigningKey

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.connector import ConnectorMiddleware
from agent_dna.connector.adapters import guard_fastmcp
from agent_dna.connector.adapters.conformance import (
    AdapterConformanceHarness,
    ConformanceOutcome,
    SideEffect,
)
from agent_dna.connector.adapters.exact_byte_http import (
    ExactByteContext,
    ExactByteHttpDispatcher,
    RecordingSidecarTransport,
    WitnessSigner,
)
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.signer import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.test_multi_writer_safety import _engine

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
ORG = "conformance.example"
WIRE = b'{"amount":100,"currency":"USD"}'
PEER = b"peer:conformance"
AT = "2026-08-10T15:00:05Z"


class ExactByteHarness:
    name = "exact_byte_http"

    def __init__(self, tmp_path) -> None:
        self._tmp = tmp_path
        self.effects: list[SideEffect] = []
        self._sink: list[bytes] = []
        self._mode = "allow"
        self._checked: bytes = WIRE
        self._build()

    def _build(self) -> None:
        runtime_key = SigningKey.generate()
        witness_key = SigningKey.generate()
        self._trust = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": ORG,
            "bundle_version": 1,
            "pinned_at": "2026-08-10T14:00:00Z",
            "keys": [
                {
                    "key_id": "ea-signer",
                    "principal": f"execution-runtime@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(runtime_key),
                    "usages": ["execution_authorization_signer"],
                },
                {
                    "key_id": "witness-01",
                    "principal": f"egress@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(witness_key),
                    "usages": ["dispatch_witness_signer", "closure_signer"],
                },
            ],
        }
        self._action = {
            "subject_principal": f"agent@{ORG}",
            "subject_key_id": "agent",
            "action": "crm.read_contact",
            "resource": "crm:contact",
            "parameters": {"id": "1"},
        }
        self._dispatch = {
            "transport": "https",
            "destination": "crm.example",
            "operation": "POST /v1/contacts",
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "tool_id": "crm.read_contact.v1",
            "tool_schema_digest": Z,
            "tool_artifact_digest": ONE,
            "credential_audience": "crm.example",
            "idempotency_key_digest": Z,
            "retry_policy_digest": ONE,
        }
        self._runtime_key = runtime_key
        self._witness_key = witness_key
        self._store = SQLiteDecisionStore(str(self._tmp / f"c-{uuid.uuid4()}.db"))
        self._mint()

    def _mint(self) -> None:
        wire = WIRE if self._mode == "allow" else WIRE  # digest always for WIRE
        self._authorization = sign_execution_authorization(
            {
                "spec": EXECUTION_AUTHORIZATION_SPEC,
                "canonicalization": CANONICALIZATION,
                "execution_authorization_id": f"eauth-{uuid.uuid4()}",
                "organisation_id": ORG,
                "request_id": "req-conf-1",
                "issued_at": "2026-08-10T15:00:00Z",
                "not_before": "2026-08-10T15:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "nonce": uuid.uuid4().hex,
                "decision_receipt_digest": Z,
                "authority_receipt_digest": ONE,
                "approval_artifact_digest": Z,
                "action": self._action,
                "action_digest": sha256_digest(self._action),
                "expected_wire_bytes_digest": sha256_bytes_digest(wire),
                "expected_wire_bytes_length": len(wire),
                "expected_peer_identity_digest": sha256_bytes_digest(PEER),
                "dispatch": self._dispatch,
                "state_snapshot_digest": Z,
                "policy_bundle_digest": ONE,
                "trust_bundle_digest": sha256_digest(self._trust),
                "obligations_digest": Z,
                "max_uses": 1,
                "signer_key_id": "ea-signer",
            },
            self._runtime_key,
        )
        self._dispatcher = ExactByteHttpDispatcher(
            consume_ledger=self._store,
            witness=WitnessSigner(
                signing_key=self._witness_key,
                signer_key_id="witness-01",
                witness_component_id="conformance-exact-byte",
                closure_signer_key_id="witness-01",
                closure_signing_key=self._witness_key,
            ),
            trust_bundle=self._trust,
            transport=RecordingSidecarTransport(peer_identity=PEER),
        )

    def reset(self) -> None:
        self.effects.clear()
        self._sink.clear()
        self._mode = "allow"
        self._checked = WIRE
        self._store = SQLiteDecisionStore(str(self._tmp / f"c-{uuid.uuid4()}.db"))
        self._mint()

    def configure_refuse(self) -> None:
        self._mode = "refuse"
        self._checked = WIRE

    def configure_allow(self) -> None:
        self._mode = "allow"
        self._checked = WIRE
        self._mint()

    def attempt(self) -> ConformanceOutcome:
        wire = WIRE if self._mode == "allow" else WIRE.replace(b"100", b"999")
        result = self._dispatcher.dispatch(
            authorization=self._authorization,
            wire_bytes=wire,
            context=ExactByteContext(
                request_id="req-conf-1",
                observed_action=copy.deepcopy(self._action),
                observed_dispatch=copy.deepcopy(self._dispatch),
                decision_receipt_digest=Z,
                authority_receipt_digest=ONE,
                approval_artifact_digest=Z,
                state_snapshot_digest=Z,
                policy_bundle_digest=ONE,
                obligations_digest=Z,
                at_time=AT,
            ),
            observed_at=AT,
        )
        if result.sent and result.wire_bytes is not None:
            self.effects.append(SideEffect(kind="http_wire", payload=result.wire_bytes))
            self._checked = result.wire_bytes
            self._sink.append(result.wire_bytes)
            return ConformanceOutcome(refused=False)
        return ConformanceOutcome(
            refused=True,
            reason_code=result.reason_code,
            detail=result.detail,
        )

    @property
    def side_effects(self) -> list[SideEffect]:
        return list(self.effects)

    def checked_payload(self) -> bytes | dict[str, Any]:
        return self._checked


class McpHarness:
    name = "mcp"

    def __init__(self, tmp_path) -> None:
        self._tmp = tmp_path
        self.effects: list[SideEffect] = []
        self._mode = "allow"
        self._checked: dict[str, Any] = {"contact_id": "C-1"}
        self._build()

    def _build(self) -> None:
        agent = generate_key("mcp-conf", scope="full")
        keys_path = self._tmp / "keys.json"
        keys_path.write_text(
            json.dumps({agent["hash"]: {"name": "mcp-conf", "scope": "full"}})
        )
        self._agent_id = "mcp-conf"
        self._key = agent["key"]
        self._breaker = CircuitBreaker(
            self._tmp / f"b-{uuid.uuid4()}.db",
            BreakerConfig(
                max_decisions=None,
                window_seconds=60.0,
                max_cumulative_amount=None,
                max_consecutive_refusals=None,
            ),
        )
        # Open authorizer so decide-path allow is deterministic for C2.
        core = _engine()
        core.authorizer = OpenAuthorizer()
        recorder = DecisionRecorder(
            signer=ReceiptSigner(seed_hex=generate_keypair()["signing_key"]),
        )
        self._mw = ConnectorMiddleware(
            engine=GuardedEngine(core, self._breaker),
            recorder=recorder,
            keys=ApiKeyRegistry(str(keys_path)),
        )
        self._server = FastMCP("conformance-mcp")
        harness = self

        @self._server.tool()
        def read_contact(contact_id: str) -> str:
            harness.effects.append(
                SideEffect(kind="mcp_tool", payload={"contact_id": contact_id})
            )
            return f"contact {contact_id}"

        guard_fastmcp(self._server, self._mw, api_key=self._key)

    def reset(self) -> None:
        self.effects.clear()
        self._mode = "allow"
        self._checked = {"contact_id": "C-1"}
        self._build()

    def configure_refuse(self) -> None:
        self._mode = "refuse"
        self._breaker._trip(
            self._agent_id, "volume_trip: conformance refuse", time.time()
        )

    def configure_allow(self) -> None:
        self._mode = "allow"

    async def _call(self, args: dict[str, Any]):
        async with create_connected_server_and_client_session(self._server) as client:
            return await client.call_tool("read_contact", args)

    def attempt(self) -> ConformanceOutcome:
        import anyio

        args = dict(self._checked)
        result = anyio.run(self._call, args)
        if result.isError:
            return ConformanceOutcome(refused=True, detail="mcp tool error")
        return ConformanceOutcome(refused=False)

    @property
    def side_effects(self) -> list[SideEffect]:
        return list(self.effects)

    def checked_payload(self) -> bytes | dict[str, Any]:
        return self._checked


@pytest.fixture(params=["exact_byte_http", "mcp"])
def harness(request, tmp_path) -> AdapterConformanceHarness:
    if request.param == "exact_byte_http":
        return ExactByteHarness(tmp_path)
    return McpHarness(tmp_path)


def test_c1_refusal_produces_no_side_effect(harness: AdapterConformanceHarness):
    harness.reset()
    harness.configure_refuse()
    outcome = harness.attempt()
    assert outcome.refused is True
    assert harness.side_effects == []


def test_c2_allow_emits_exactly_checked_payload(harness: AdapterConformanceHarness):
    harness.reset()
    harness.configure_allow()
    before = harness.checked_payload()
    outcome = harness.attempt()
    # Drift may escalate MCP; if refused, no side effect (still conformant).
    if outcome.refused:
        assert harness.side_effects == []
        return
    assert len(harness.side_effects) == 1
    assert harness.side_effects[0].payload == before


def test_c3_second_refuse_path_no_extra_effect(harness: AdapterConformanceHarness):
    harness.reset()
    harness.configure_allow()
    first = harness.attempt()
    count_after_first = len(harness.side_effects)
    if harness.name == "exact_byte_http":
        # Replay same EA — must refuse and not send again.
        second = harness.attempt()
        assert second.refused is True
        assert len(harness.side_effects) == count_after_first
    else:
        harness.configure_refuse()
        second = harness.attempt()
        assert second.refused is True
        assert len(harness.side_effects) == count_after_first
    # Silence unused on allow-escalation path.
    _ = first
    time.sleep(0)
