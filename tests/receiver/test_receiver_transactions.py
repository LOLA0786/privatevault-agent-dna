"""One business transaction, one admitted effect (ADR 0030).

Follow-up review, 20 October 2026, item 2: a fresh decision for the same
invoice mints a fresh permit, and each permit is admitted once, so the same
invoice could be paid twice. The receiver now claims a declared business
key from the bound body once, whoever minted the permit.

Claims -> tests:
  - A second permit for the same invoice is refused (409, signed receipt)
    without consuming that permit; another invoice is admitted
    -> test_second_permit_for_the_same_invoice_is_refused
  - While the first request is still in flight (no answer yet) the second
    is refused -> test_duplicate_is_refused_while_the_first_is_in_flight
  - Concurrent permits for one invoice, through two gate instances on one
    ledger: exactly one admitted -> test_concurrent_permits_admit_one
  - An upstream answer meaning "not acted on" frees the key
    -> test_not_executed_answer_frees_the_key[*]
  - 5xx, 408, 409, 429, an exception or no answer leave the key blocked
    until an operator reconciles it; reconciled "not executed" frees it,
    "executed" keeps it refused for good
    -> test_uncertain_answers_block_until_reconciled[*]
  - A crash between admission and the answer leaves the claim open across
    a restart; the reconciliation tool lists it and exits 1
    -> test_crash_before_the_answer_keeps_the_key_blocked
  - A missing or unusable key is refused without burning the permit
    -> test_unusable_key_is_refused_without_burning_the_permit[*]
  - Undeclared operations behave as before -> test_undeclared_operation_is_unchanged
  - Bad declarations stop the gate -> test_bad_declarations_are_refused[*]
  - HTTP: the proxy records the upstream status, sends the opaque
    Idempotency-Key, and an unreachable upstream is INDETERMINATE; the
    middleware records the app's status or its exception
    -> test_proxy_*, test_middleware_*
  - Receiver kit: PV_RECEIVER_TRANSACTION_KEYS is parsed and validated
    -> test_kit_transaction_keys[*]
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from agent_dna.receiver import gate as g
from agent_dna.receiver.asgi import ReceiverGateMiddleware, ReceiverGateProxy
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.receiver.receipts import verify_receiver_receipt_chain
from agent_dna.receiver.transactions import (
    CLAIMED,
    EXECUTED,
    INDETERMINATE,
    NOT_EXECUTED,
    transaction_reference,
)
from tools import receiver_transactions as tool

from ._world import (
    DESTINATION,
    METHOD,
    NOW,
    OPERATION,
    ORG,
    PARAMETERS,
    PATH,
    RECEIVER,
    World,
    wire_for,
)

KEYS = {OPERATION: "invoiceId"}


def _params(invoice="INV-1001", **extra):
    return {**PARAMETERS, "invoiceId": invoice, **extra}


def _send(world, permit, params, at=NOW):
    return world.gate.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, encode_permit_header(permit))],
        body=wire_for(params),
        received_at=at,
    )


def _pay(world, invoice="INV-1001", **extra):
    params = _params(invoice, **extra)
    permit = world.permit(parameters=params)
    return permit, _send(world, permit, params)


def _chain_ok(world):
    report = verify_receiver_receipt_chain(
        list(world.ledger.iter_receipts()),
        receiver_public_keys=world.published_keys,
        receiver_id=RECEIVER,
    )
    assert report.ok, report.failures
    return report


def _state(world, invoice="INV-1001"):
    (row,) = [r for r in world.ledger.transactions() if r["transaction_key"] == invoice]
    return row["state"]


def _resolve(world, resolution, invoice="INV-1001"):
    return tool.main(
        [
            "--ledger",
            str(world.ledger_path),
            "resolve",
            "--org",
            ORG,
            "--operation",
            OPERATION,
            "--key",
            invoice,
            "--as",
            resolution,
            "--by",
            "ops: reviewer",
            "--note",
            "checked core banking",
        ]
    )


# ------------------------------------------------------------------ gate


def test_second_permit_for_the_same_invoice_is_refused(tmp_path):
    w = World(tmp_path, transaction_keys=KEYS)
    _, first = _pay(w)
    assert first.admitted and first.transaction == (OPERATION, "INV-1001")
    assert w.gate.record_outcome(first, 200) == EXECUTED

    second_permit, second = _pay(w)
    assert not second.admitted
    assert second.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION
    assert second.http_status == 409
    assert second.receipt["outcome"] == "REFUSED"
    assert second.receipt["reason_code"] == g.RECEIVER_DUPLICATE_TRANSACTION
    assert not w.ledger.is_consumed(ORG, second_permit["execution_authorization_id"])

    _, other = _pay(w, "INV-1002")
    assert other.admitted
    _chain_ok(w)


def test_duplicate_is_refused_while_the_first_is_in_flight(tmp_path):
    w = World(tmp_path, transaction_keys=KEYS)
    _, first = _pay(w)
    assert first.admitted  # forwarded; the upstream has not answered yet
    _, second = _pay(w)
    assert second.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION
    assert _state(w) == CLAIMED
    w.gate.record_outcome(first, 201)  # the delayed answer arrives
    assert _state(w) == EXECUTED
    _, third = _pay(w)
    assert third.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION


def test_concurrent_permits_admit_one(tmp_path):
    w = World(tmp_path, transaction_keys=KEYS)
    # a second gate instance (another worker process) on the same ledger file
    other = ReceiverGate(
        receiver_id=RECEIVER,
        destinations=frozenset({DESTINATION}),
        trust_bundle=w.bundle,
        ledger=ReceiverLedger(w.ledger_path),
        receipt_signing_key=w.receipt_key,
        receipt_key_id="bank-receiver-01",
        transaction_keys=KEYS,
    )
    params = _params()
    permits = [w.permit(parameters=params) for _ in range(16)]
    results = []
    barrier = threading.Barrier(16)

    def worker(i):
        gate = w.gate if i % 2 else other
        barrier.wait()
        results.append(
            gate.check(
                method=METHOD,
                path=PATH,
                headers=[(PERMIT_HEADER, encode_permit_header(permits[i]))],
                body=wire_for(params),
                received_at=NOW,
            )
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r.admitted for r in results) == 1
    assert {r.reason_code for r in results if not r.admitted} == {
        g.RECEIVER_DUPLICATE_TRANSACTION
    }
    assert _chain_ok(w).count == 16


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 415, 422])
def test_not_executed_answer_frees_the_key(tmp_path, status):
    w = World(tmp_path, transaction_keys=KEYS)
    _, first = _pay(w)
    assert w.gate.record_outcome(first, status) == NOT_EXECUTED
    _, retry = _pay(w)
    assert retry.admitted
    assert [
        e["to_state"] for e in w.ledger.transaction_events(ORG, OPERATION, "INV-1001")
    ] == [
        CLAIMED,
        NOT_EXECUTED,
        CLAIMED,
    ]


@pytest.mark.parametrize("status", [500, 502, 503, 504, 408, 409, 425, 429, 302, None])
def test_uncertain_answers_block_until_reconciled(tmp_path, status):
    w = World(tmp_path, transaction_keys=KEYS)
    _, first = _pay(w)
    assert w.gate.record_outcome(first, status) == INDETERMINATE
    _, blocked = _pay(w)
    assert blocked.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION

    assert _resolve(w, "not-executed") == 0
    _, retry = _pay(w)
    assert retry.admitted
    assert w.gate.record_outcome(retry, 503) == INDETERMINATE
    assert _resolve(w, "executed") == 0
    assert _state(w) == EXECUTED
    _, after = _pay(w)
    assert after.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION
    assert _resolve(w, "not-executed") == 2  # EXECUTED is final
    events = w.ledger.transaction_events(ORG, OPERATION, "INV-1001")
    assert [e["actor"] for e in events if e["note"]] == ["ops: reviewer"] * 2


def test_crash_before_the_answer_keeps_the_key_blocked(tmp_path, capsys):
    w = World(tmp_path, transaction_keys=KEYS)
    _, first = _pay(w)
    assert first.admitted
    del w.gate  # the process dies before the upstream answers
    restarted = World.__new__(World)
    restarted.__dict__.update(w.__dict__)
    restarted.ledger = ReceiverLedger(w.ledger_path)
    restarted.gate = ReceiverGate(
        receiver_id=RECEIVER,
        destinations=frozenset({DESTINATION}),
        trust_bundle=w.bundle,
        ledger=restarted.ledger,
        receipt_signing_key=w.receipt_key,
        receipt_key_id="bank-receiver-01",
        transaction_keys=KEYS,
    )
    _, second = _pay(restarted)
    assert second.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION
    capsys.readouterr()
    assert tool.main(["--ledger", str(w.ledger_path), "list", "--open"]) == 1
    listed = capsys.readouterr().out
    assert '"state": "CLAIMED"' in listed and "INV-1001" in listed
    assert _resolve(restarted, "not-executed") == 0
    assert tool.main(["--ledger", str(w.ledger_path), "list", "--open"]) == 0


@pytest.mark.parametrize(
    "params",
    [
        {**PARAMETERS},
        _params(""),
        _params(" INV-1"),
        _params(True),
        _params("INV\n1"),
        _params("x" * 257),
        _params({"nested": "INV-1"}),
        _params(["INV-1"]),
        _params(None),
    ],
    ids=[
        "missing",
        "empty",
        "untrimmed",
        "bool",
        "control-char",
        "long",
        "object",
        "list",
        "null",
    ],
)
def test_unusable_key_is_refused_without_burning_the_permit(tmp_path, params):
    w = World(tmp_path, transaction_keys=KEYS)
    permit = w.permit(parameters=params)
    decision = _send(w, permit, params)
    assert decision.reason_code == g.RECEIVER_TRANSACTION_KEY_INVALID
    assert decision.http_status == 400
    assert not w.ledger.is_consumed(ORG, permit["execution_authorization_id"])
    assert w.ledger.transactions() == []


def test_integer_keys_and_nested_paths(tmp_path):
    w = World(tmp_path, transaction_keys={OPERATION: "ref.invoice"})
    params = {**PARAMETERS, "ref": {"invoice": 7731}}
    first = _send(w, w.permit(parameters=params), params)
    assert first.transaction == (OPERATION, "7731")
    second = _send(w, w.permit(parameters=params), params)
    assert second.reason_code == g.RECEIVER_DUPLICATE_TRANSACTION


def test_undeclared_operation_is_unchanged(tmp_path):
    w = World(tmp_path)
    _, first = _pay(w)
    _, second = _pay(w)
    assert first.admitted and second.admitted  # the documented old boundary
    assert first.transaction is None
    assert w.gate.record_outcome(first, 200) is None
    assert w.ledger.transactions() == []


@pytest.mark.parametrize(
    "keys",
    [{"GET /api/v1/x": "id"}, {"POST": "id"}, {OPERATION: ""}, {OPERATION: "a..b"}],
    ids=["read", "no-path", "empty-field", "empty-segment"],
)
def test_bad_declarations_are_refused(tmp_path, keys):
    with pytest.raises(ValueError):
        World(tmp_path, transaction_keys=keys)


# ------------------------------------------------------------------ HTTP


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _live(world, invoice="INV-1001"):
    params = _params(invoice)
    permit = world.permit(
        parameters=params,
        not_before="2026-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    return permit, wire_for(params)


class _Upstream(BaseHTTPRequestHandler):
    status = 200
    seen: list = []

    def do_POST(self):  # noqa: N802 - stdlib handler name
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        type(self).seen.append(dict(self.headers))
        self.send_response(type(self).status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


@pytest.fixture
def upstream():
    _Upstream.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


async def _post(app, permit, body):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bank"
    ) as client:
        return await client.post(
            PATH,
            content=body,
            headers={
                PERMIT_HEADER: encode_permit_header(permit),
                "Content-Type": "application/json",
                "Idempotency-Key": "client-chosen",
            },
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,state", [(201, EXECUTED), (422, NOT_EXECUTED), (503, INDETERMINATE)]
)
async def test_proxy_records_the_upstream_answer(tmp_path, upstream, status, state):
    _Upstream.status = status
    w = World(tmp_path, transaction_keys=KEYS)
    base = f"http://127.0.0.1:{upstream.server_address[1]}"
    proxy = ReceiverGateProxy(
        w.gate, base, allow_http_upstream=True, idempotency_header="Idempotency-Key"
    )
    permit, body = _live(w)
    response = await _post(proxy, permit, body)
    assert response.status_code == status
    assert _state(w) == state
    (headers,) = _Upstream.seen
    assert headers["Idempotency-Key"] == transaction_reference(
        ORG, OPERATION, "INV-1001"
    )
    again, body = _live(w)
    second = await _post(proxy, again, body)
    if state == NOT_EXECUTED:  # freed: the retry reaches the upstream
        assert second.status_code == status and len(_Upstream.seen) == 2
    else:  # refused at the gate: the duplicate never reaches the upstream
        assert second.status_code == 409
        assert second.json()["reason_code"] == g.RECEIVER_DUPLICATE_TRANSACTION
        assert len(_Upstream.seen) == 1


@pytest.mark.anyio
async def test_proxy_unreachable_upstream_is_indeterminate(tmp_path):
    w = World(tmp_path, transaction_keys=KEYS)
    proxy = ReceiverGateProxy(w.gate, "http://127.0.0.1:1", allow_http_upstream=True)
    permit, body = _live(w)
    response = await _post(proxy, permit, body)
    assert response.status_code == 502
    assert response.json()["upstream"] == "INDETERMINATE"
    assert _state(w) == INDETERMINATE


@pytest.mark.anyio
async def test_middleware_records_the_apps_answer_or_failure(tmp_path):
    w = World(tmp_path, transaction_keys=KEYS)

    async def ok_app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    permit, body = _live(w, "INV-A")
    assert (
        await _post(ReceiverGateMiddleware(ok_app, w.gate), permit, body)
    ).status_code == 201
    assert _state(w, "INV-A") == EXECUTED

    async def broken_app(scope, receive, send):
        await receive()
        raise RuntimeError("core banking timed out")

    permit, body = _live(w, "INV-B")
    with pytest.raises(RuntimeError):
        await _post(ReceiverGateMiddleware(broken_app, w.gate), permit, body)
    assert _state(w, "INV-B") == INDETERMINATE


# ------------------------------------------------------------- receiver kit


@pytest.mark.parametrize(
    "raw,ok",
    [
        ('{"POST /api/v1/accounttransfers": "invoiceId"}', True),
        ("", True),
        ("not json", False),
        ('["POST /x"]', False),
        ('{"POST /x": 3}', False),
        ('{"GET /x": "id"}', False),
    ],
    ids=["valid", "unset", "not-json", "list", "non-string", "read"],
)
def test_kit_transaction_keys(tmp_path, raw, ok):
    from nacl.signing import SigningKey

    from network.receiver_kit import config
    from tests.network.test_receiver_kit import _env

    env = _env(
        tmp_path,
        SigningKey.generate(),
        SigningKey.generate(),
        PV_RECEIVER_TRANSACTION_KEYS=raw,
        PV_RECEIVER_IDEMPOTENCY_HEADER="Idempotency-Key",
    )
    if not ok:
        with pytest.raises((config.ConfigError, ValueError)):
            config.build_gate(config.settings_from_env(env))
        return
    settings = config.settings_from_env(env)
    gate = config.build_gate(settings)
    assert dict(gate.transaction_keys) == (
        {"POST /api/v1/accounttransfers": "invoiceId"} if raw else {}
    )
    assert "transaction keys" in config.describe(settings, gate)
