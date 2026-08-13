"""Live TLS sidecar: hostname pin, observed HTTP status, fail-closed isolation."""

from __future__ import annotations

import copy
import ssl
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.closure_v01 import verify_closure_chain
from agent_dna.connector.adapters.exact_byte_http import (
    DISPATCH_CREDENTIAL_MISMATCH,
    DISPATCH_HANDSHAKE_FAILED,
    DISPATCH_TRANSPORT_REFUSED,
    OUTCOME_CONTROL_FAILURE,
    OUTCOME_EXECUTED,
    OUTCOME_INDETERMINATE,
    ExactByteContext,
    ExactByteHttpDispatcher,
    TlsHttpsSidecarTransport,
    WitnessSigner,
    serialize_json_payload,
)
from agent_dna.dispatch_v01 import verify_dispatch_witness
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.sqlite_store import SQLiteDecisionStore

ORG = "tls.example"
PAYLOAD = {"account": "4471", "amount": 400000, "currency": "INR"}
WIRE = serialize_json_payload(PAYLOAD)
AT = "2026-08-10T12:00:05Z"
Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)


class _TlsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        delay = float(getattr(self.server, "delay_s", 0.0))
        if delay:
            time.sleep(delay)
        status = int(getattr(self.server, "response_status", 200))
        body = bytes(getattr(self.server, "response_body", b'{"ok":true}'))
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionError, ssl.SSLEOFError):
            return

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _TlsServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    response_status = 200
    response_body = b'{"ok":true}'
    delay_s = 0.0
    accept_count = 0

    def get_request(self) -> tuple[Any, Any]:
        self.accept_count += 1
        return super().get_request()


class CountingTlsTransport(TlsHttpsSidecarTransport):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sessions: list[Any] = []

    def connect(self, destination: str, *, credential_audience: str = ""):
        session = super().connect(destination, credential_audience=credential_audience)
        self.sessions.append(session)
        return session


def _require_openssl() -> None:
    try:
        subprocess.run(
            ["openssl", "version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"openssl is required for sidecar TLS tests: {exc}")


def _make_cert(directory: Path, *, sans: str) -> tuple[Path, Path]:
    _require_openssl()
    cfg = directory / "openssl.cnf"
    cfg.write_text(
        "[req]\n"
        "distinguished_name=dn\n"
        "x509_extensions=v3\n"
        "prompt=no\n"
        "[dn]\n"
        "CN=localhost\n"
        "[v3]\n"
        f"subjectAltName={sans}\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-config",
            str(cfg),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert, key


@contextmanager
def _serve_tls(
    cert: Path,
    key: Path,
    *,
    status: int = 200,
    body: bytes = b'{"ok":true}',
    delay_s: float = 0.0,
) -> Iterator[_TlsServer]:
    httpd = _TlsServer(("127.0.0.1", 0), _TlsHandler)
    httpd.response_status = status
    httpd.response_body = body
    httpd.delay_s = delay_s
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _bundle_for(runtime_key: SigningKey, witness_key: SigningKey) -> dict[str, Any]:
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
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


def _tls_world(
    tmp_path: Path,
    *,
    destination: str,
    peer: bytes,
    audience: str = "payments.store.example",
):
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    trust_bundle = _bundle_for(runtime_key, witness_key)
    action = {
        "subject_principal": f"treasury@{ORG}",
        "subject_key_id": "treasury",
        "action": "payments.initiate_wire",
        "resource": "payments:wire",
        "parameters": {"amount": 400000},
    }
    dispatch = {
        "transport": "https",
        "destination": destination,
        "operation": "POST /v1/wires",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.initiate_wire.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": audience,
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
    }
    ea_id = f"eauth-{uuid.uuid4()}"
    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ea_id,
            "organisation_id": ORG,
            "request_id": f"req-tls-{uuid.uuid4().hex[:8]}",
            "issued_at": "2026-08-10T12:00:00Z",
            "not_before": "2026-08-10T12:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": Z,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": Z,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
            "expected_wire_bytes_length": len(WIRE),
            "expected_peer_identity_digest": sha256_bytes_digest(peer),
            "dispatch": dispatch,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": Z,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        runtime_key,
    )
    store = SQLiteDecisionStore(str(tmp_path / f"consume-{uuid.uuid4().hex}.db"))
    return {
        "authorization": authorization,
        "trust_bundle": trust_bundle,
        "action": action,
        "dispatch": dispatch,
        "witness_key": witness_key,
        "store": store,
        "ea_id": ea_id,
    }


def _context(w: dict[str, Any]) -> ExactByteContext:
    return ExactByteContext(
        request_id=w["authorization"]["request_id"],
        observed_action=copy.deepcopy(w["action"]),
        observed_dispatch=copy.deepcopy(w["dispatch"]),
        decision_receipt_digest=Z,
        authority_receipt_digest=ONE,
        approval_artifact_digest=Z,
        state_snapshot_digest=Z,
        policy_bundle_digest=ONE,
        obligations_digest=Z,
        at_time=AT,
    )


def _dispatcher(w: dict[str, Any], transport: TlsHttpsSidecarTransport):
    return ExactByteHttpDispatcher(
        consume_ledger=w["store"],
        witness=WitnessSigner(
            signing_key=w["witness_key"],
            signer_key_id="witness-01",
            witness_component_id="sidecar-tls-test",
            closure_signer_key_id="witness-01",
            closure_signing_key=w["witness_key"],
        ),
        trust_bundle=w["trust_bundle"],
        transport=transport,
    )


def _peer_der(cert: Path) -> bytes:
    return ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="utf-8"))


def _dispatch(w: dict[str, Any], transport: TlsHttpsSidecarTransport):
    return _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )


@pytest.mark.parametrize(
    ("status", "outcome", "response_status"),
    [
        (200, "ACKNOWLEDGED", "200"),
        (401, "REJECTED", "401"),
        (500, "TRANSPORT_ERROR", None),
    ],
)
def test_tls_closure_status_from_observed_http(
    tmp_path, status, outcome, response_status
):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key, status=status) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)
        result = _dispatch(w, transport)
    assert result.outcome == OUTCOME_EXECUTED
    assert result.closure is not None
    assert result.closure["dispatch_outcome"] == outcome
    assert result.closure["response_status"] == response_status
    assert all(session.closed for session in transport.sessions)
    chain = verify_closure_chain(
        w["authorization"],
        result.witness,
        result.closure,
        w["trust_bundle"],
    )
    assert chain.ok


def test_tls_hostname_and_certificate_verification(tmp_path):
    good_dir = tmp_path / "good"
    bad_dir = tmp_path / "bad"
    good_dir.mkdir()
    bad_dir.mkdir()
    good_cert, good_key = _make_cert(good_dir, sans="DNS:localhost,IP:127.0.0.1")
    other_cert, _other_key = _make_cert(bad_dir, sans="DNS:evil.example")
    peer = _peer_der(good_cert)
    with _serve_tls(good_cert, good_key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        ok = _dispatch(
            w,
            CountingTlsTransport(ca_file=str(good_cert), timeout_s=5.0),
        )
        assert ok.outcome == OUTCOME_EXECUTED
        boundary = verify_dispatch_witness(
            ok.witness,
            w["authorization"],
            w["trust_bundle"],
            observed_action=w["action"],
            observed_dispatch=w["dispatch"],
            wire_bytes=WIRE,
            peer_identity_bytes=peer,
        )
        assert boundary.ok

        wrong_ca = _tls_world(tmp_path, destination=dest, peer=peer)
        refused = _dispatch(
            wrong_ca,
            CountingTlsTransport(ca_file=str(other_cert), timeout_s=5.0),
        )
        assert refused.outcome == OUTCOME_CONTROL_FAILURE
        assert refused.reason_code == DISPATCH_HANDSHAKE_FAILED
        assert not wrong_ca["store"].is_execution_authorization_consumed(
            wrong_ca["ea_id"]
        )


def test_tls_hostname_mismatch_fails_handshake(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:evil.example")
    peer = _peer_der(cert)
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)
        result = _dispatch(w, transport)
        assert result.outcome == OUTCOME_CONTROL_FAILURE
        assert result.reason_code == DISPATCH_HANDSHAKE_FAILED
        assert transport.sessions == []
        assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_forged_authorization_opens_zero_connections(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        forged = copy.deepcopy(w["authorization"])
        forged["signature"] = "0" * 128
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)
        result = _dispatcher(w, transport).dispatch(
            authorization=forged,
            wire_bytes=WIRE,
            context=_context(w),
            observed_at=AT,
        )
        assert result.sent is False
        assert result.outcome == OUTCOME_CONTROL_FAILURE
        assert server.accept_count == 0
        assert transport.sessions == []
        assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_concurrent_dispatch_isolation(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w1 = _tls_world(tmp_path, destination=dest, peer=peer)
        w2 = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)

        def _run(world: dict[str, Any]):
            return _dispatch(world, transport)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(_run, w1)
            second = pool.submit(_run, w2)
            results = [first.result(timeout=10), second.result(timeout=10)]
        assert all(item.outcome == OUTCOME_EXECUTED for item in results)
        assert len(transport.sessions) == 2
        assert all(session.closed for session in transport.sessions)
        assert transport.sessions[0] is not transport.sessions[1]


def test_connection_cleanup_on_peer_refusal(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=b"not-the-real-der")
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)
        result = _dispatch(w, transport)
        assert result.sent is False
        assert result.outcome == OUTCOME_CONTROL_FAILURE
        assert transport.sessions
        assert all(session.closed for session in transport.sessions)
        assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_missing_closure_signer_usage_fails_closed(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    dest = "https://127.0.0.1:1"
    w = _tls_world(tmp_path, destination=dest, peer=peer)
    broken = copy.deepcopy(w["trust_bundle"])
    broken["keys"][1]["usages"] = ["dispatch_witness_signer"]
    with pytest.raises(RuntimeError, match="missing required key usages"):
        ExactByteHttpDispatcher(
            consume_ledger=w["store"],
            witness=WitnessSigner(
                signing_key=w["witness_key"],
                signer_key_id="witness-01",
                witness_component_id="sidecar-tls-test",
            ),
            trust_bundle=broken,
            transport=CountingTlsTransport(ca_file=str(cert)),
        )


def test_credential_audience_mismatch_never_connects(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(
            tmp_path,
            destination=dest,
            peer=peer,
            audience="payments.store.example",
        )
        transport = CountingTlsTransport(
            ca_file=str(cert),
            timeout_s=5.0,
            credentials_headers={"Authorization": "Bearer secret"},
            allowed_destinations=frozenset([dest]),
            allowed_audiences=frozenset(["other.example"]),
        )
        result = _dispatch(w, transport)
        assert result.reason_code == DISPATCH_CREDENTIAL_MISMATCH
        assert result.sent is False
        assert server.accept_count == 0
        assert transport.sessions == []
        assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_oversized_response_is_indeterminate(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    huge = b"x" * 2048
    with _serve_tls(cert, key, body=huge) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(
            ca_file=str(cert),
            timeout_s=5.0,
            max_response_bytes=512,
        )
        result = _dispatch(w, transport)
        assert result.outcome == OUTCOME_INDETERMINATE
        assert result.reason_code == DISPATCH_TRANSPORT_REFUSED
        assert "SidecarResponseOversizeError" in (result.detail or "")
        assert w["store"].is_execution_authorization_consumed(w["ea_id"])
        assert all(session.closed for session in transport.sessions)


def test_timeout_after_write_is_indeterminate(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key, delay_s=1.5) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=0.2)
        result = _dispatch(w, transport)
        assert result.outcome == OUTCOME_INDETERMINATE
        assert result.reason_code == DISPATCH_TRANSPORT_REFUSED
        assert w["store"].is_execution_authorization_consumed(w["ea_id"])
        assert all(session.closed for session in transport.sessions)


def test_timestamp_ordering_observed_before_closed(tmp_path):
    cert, key = _make_cert(tmp_path, sans="DNS:localhost,IP:127.0.0.1")
    peer = _peer_der(cert)
    with _serve_tls(cert, key) as server:
        dest = f"https://127.0.0.1:{server.server_address[1]}"
        w = _tls_world(tmp_path, destination=dest, peer=peer)
        transport = CountingTlsTransport(ca_file=str(cert), timeout_s=5.0)
        result = _dispatch(w, transport)
    assert result.outcome == OUTCOME_EXECUTED
    assert result.witness is not None
    assert result.closure is not None
    observed = datetime.fromisoformat(
        result.witness["observed_at"].replace("Z", "+00:00")
    )
    closed = datetime.fromisoformat(result.closure["closed_at"].replace("Z", "+00:00"))
    assert observed <= closed
    assert "." in result.witness["observed_at"]
    assert "." in result.closure["closed_at"]
    assert result.witness["observed_at"] != AT
