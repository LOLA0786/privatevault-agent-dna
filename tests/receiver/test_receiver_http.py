"""Receiver gate over HTTP, and the agent-side sidecar presenting the permit.

Claims → tests:
  - Refused requests never reach the protected app
    → test_middleware_refusal_never_reaches_app
  - Admitted request reaches the app with the exact bound body, permit
    header stripped, receipt digest returned
    → test_middleware_admits_exact_body_and_strips_permit
  - Reverse proxy in front of an unmodified upstream: direct call without a
    permit never reaches it; a permitted call reaches it once with exact bytes
    → test_proxy_blocks_bypass_and_forwards_permitted_call_once
  - Oversized body refused before the upstream is touched
    → test_proxy_oversize_body_refused
  - The exact-byte sidecar attaches a permit the receiver admits for the very
    bytes it wrote; without the flag no header is sent
    → test_sidecar_permit_header_is_admitted_by_receiver
"""

from __future__ import annotations

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.connector.adapters.exact_byte_http import (
    OUTCOME_EXECUTED,
    ExactByteContext,
    ExactByteHttpDispatcher,
    RecordingSidecarTransport,
    WitnessSigner,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.receiver import gate as g
from agent_dna.receiver.asgi import (
    RECEIPT_HEADER,
    ReceiverGateMiddleware,
    ReceiverGateProxy,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.sqlite_store import SQLiteDecisionStore

from ._world import PARAMETERS, PATH, World, wire_for

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _late_permit(world):
    # Valid for the real wall clock: these tests do not inject received_at.
    return world.permit(
        not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z"
    )


class _App:
    def __init__(self):
        self.calls = []

    async def __call__(self, scope, receive, send):
        message = await receive()
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        self.calls.append((scope["method"], scope["path"], message["body"], headers))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


async def test_middleware_refusal_never_reaches_app(tmp_path):
    w = World(tmp_path)
    app = _App()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ReceiverGateMiddleware(app, w.gate)),
        base_url="http://bank",
    )
    resp = await client.post(PATH, content=wire_for(PARAMETERS))
    assert resp.status_code == 403
    assert resp.json()["reason_code"] == g.RECEIVER_PERMIT_MISSING
    assert resp.json()["receipt_sequence"] == 1
    assert app.calls == []


async def test_middleware_admits_exact_body_and_strips_permit(tmp_path):
    w = World(tmp_path)
    app = _App()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=ReceiverGateMiddleware(app, w.gate)),
        base_url="http://bank",
    )
    permit = _late_permit(w)
    body = wire_for(PARAMETERS)
    resp = await client.post(
        PATH, content=body, headers={PERMIT_HEADER: encode_permit_header(permit)}
    )
    assert resp.status_code == 200
    assert len(app.calls) == 1
    method, path, seen_body, headers = app.calls[0]
    assert (method, path, seen_body) == ("POST", PATH, body)
    assert PERMIT_HEADER.lower() not in headers
    receipt = next(w.ledger.iter_receipts())
    assert resp.headers[RECEIPT_HEADER] == sha256_digest(receipt)

    replay = await client.post(
        PATH, content=body, headers={PERMIT_HEADER: encode_permit_header(permit)}
    )
    assert replay.status_code == 409
    assert len(app.calls) == 1


class _Upstream(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):  # noqa: N802 - stdlib handler name
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).seen.append((self.path, body, {k.lower() for k in self.headers}))
        payload = b'{"resourceId":1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


@pytest.fixture
def upstream():
    _Upstream.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", _Upstream.seen
    server.shutdown()


async def test_proxy_blocks_bypass_and_forwards_permitted_call_once(tmp_path, upstream):
    base, seen = upstream
    w = World(tmp_path)
    proxy = ReceiverGateProxy(w.gate, base, allow_http_upstream=True)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy), base_url="http://bank"
    )
    body = wire_for(PARAMETERS)

    bypass = await client.post(PATH, content=body)
    assert bypass.status_code == 403
    assert seen == []

    permit = _late_permit(w)
    tampered = wire_for({**PARAMETERS, "toAccountId": "MULE-666"})
    swapped = await client.post(
        PATH, content=tampered, headers={PERMIT_HEADER: encode_permit_header(permit)}
    )
    assert swapped.status_code == 403
    assert swapped.json()["reason_code"] == g.RECEIVER_WIRE_MISMATCH
    assert seen == []

    ok = await client.post(
        PATH, content=body, headers={PERMIT_HEADER: encode_permit_header(permit)}
    )
    assert ok.status_code == 200
    assert ok.json() == {"resourceId": 1}
    assert len(seen) == 1
    path, upstream_body, upstream_headers = seen[0]
    assert (path, upstream_body) == (PATH, body)
    assert PERMIT_HEADER.lower() not in upstream_headers

    replay = await client.post(
        PATH, content=body, headers={PERMIT_HEADER: encode_permit_header(permit)}
    )
    assert replay.status_code == 409
    assert len(seen) == 1


async def test_proxy_oversize_body_refused(tmp_path, upstream):
    base, seen = upstream
    w = World(tmp_path, max_body_bytes=16)
    proxy = ReceiverGateProxy(w.gate, base, allow_http_upstream=True)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=proxy), base_url="http://bank"
    )
    resp = await client.post(PATH, content=b"x" * 64)
    assert resp.status_code == 413
    assert resp.json()["reason_code"] == g.RECEIVER_BODY_TOO_LARGE
    assert seen == []


def test_proxy_refuses_plain_http_upstream_by_default(tmp_path):
    w = World(tmp_path)
    with pytest.raises(ValueError, match="allow_http_upstream"):
        ReceiverGateProxy(w.gate, "http://core-banking:8080")


# --------------------------------------------------- agent sidecar → receiver

Z = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
ORG = "lender.example"
DEST = "https://core-banking.bank.example:8443"
AUD = "core-banking.bank.example"
PEER = b"tls-spki:core-banking.bank.example"


def _sidecar_world(tmp_path):
    runtime_key, witness_key = SigningKey.generate(), SigningKey.generate()
    bundle = {
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
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": f"egress-witness@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }
    wire = wire_for(PARAMETERS)
    action = {
        "subject_principal": f"servicing-agent@{ORG}",
        "subject_key_id": "servicing-agent",
        "action": "loan.disburse_transfer",
        "resource": "account:A-1001",
        "parameters": dict(PARAMETERS),
    }
    dispatch = {
        "transport": "https",
        "destination": DEST,
        "operation": f"POST {PATH}",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "corebanking.accounttransfers.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": AUD,
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
        "serialization": "pv-json-parameters/0.1",
    }
    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": f"eauth-{uuid.uuid4()}",
            "organisation_id": ORG,
            "request_id": "req-1",
            "issued_at": "2026-01-01T00:00:00Z",
            "not_before": "2026-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": Z,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": Z,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER),
            "dispatch": dispatch,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(bundle),
            "obligations_digest": Z,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        runtime_key,
    )
    context = ExactByteContext(
        request_id="req-1",
        observed_action=action,
        observed_dispatch=dispatch,
        decision_receipt_digest=Z,
        authority_receipt_digest=ONE,
        approval_artifact_digest=Z,
        state_snapshot_digest=Z,
        policy_bundle_digest=ONE,
        obligations_digest=Z,
        at_time="2026-10-08T12:00:00Z",
    )
    return bundle, witness_key, authorization, context, wire


def _dispatcher(tmp_path, bundle, witness_key, transport, *, attach):
    return ExactByteHttpDispatcher(
        consume_ledger=SQLiteDecisionStore(str(tmp_path / "agent-side.db")),
        witness=WitnessSigner(
            signing_key=witness_key,
            signer_key_id="witness-01",
            witness_component_id="receiver-e2e",
            closure_signer_key_id="witness-01",
            closure_signing_key=witness_key,
        ),
        trust_bundle=bundle,
        transport=transport,
        attach_permit_header=attach,
    )


def test_sidecar_permit_header_is_admitted_by_receiver(tmp_path):
    bundle, witness_key, authorization, context, wire = _sidecar_world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(
        tmp_path, bundle, witness_key, transport, attach=True
    ).dispatch(authorization=authorization, wire_bytes=wire, context=context)
    assert result.outcome == OUTCOME_EXECUTED
    assert transport.writes == [wire]
    header = transport.last_extra_headers[PERMIT_HEADER]

    receiver = ReceiverGate(
        receiver_id=AUD,
        destinations=frozenset({DEST}),
        trust_bundle=bundle,
        ledger=ReceiverLedger(tmp_path / "bank-side.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="bank-receiver-01",
    )
    admitted = receiver.check(
        method="POST",
        path=PATH,
        headers=[(PERMIT_HEADER, header)],
        body=transport.writes[0],
    )
    assert admitted.admitted, admitted.reason_code
    again = receiver.check(
        method="POST", path=PATH, headers=[(PERMIT_HEADER, header)], body=wire
    )
    assert again.reason_code == g.RECEIVER_PERMIT_CONSUMED


def test_sidecar_without_flag_sends_no_permit(tmp_path):
    bundle, witness_key, authorization, context, wire = _sidecar_world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(
        tmp_path, bundle, witness_key, transport, attach=False
    ).dispatch(authorization=authorization, wire_bytes=wire, context=context)
    assert result.outcome == OUTCOME_EXECUTED
    assert transport.last_extra_headers == {}
