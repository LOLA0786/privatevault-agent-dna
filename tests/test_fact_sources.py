"""ADR 0045: decision facts checked against the system of record.

Claims -> tests:
  - PV_FACT_SOURCES is validated; malformed values refuse to start
    -> test_config, test_bad_config_refuses[*]
  - Facts are derived from refund-facts/1 for the requested amount and payee
    -> test_derive
  - A matching action passes; a wrong, missing or wrong-typed fact refuses
    and names it; unknown orders, malformed answers, server errors and
    timeouts refuse -> test_check[*], test_unreadable[*]
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_dna import fact_sources as fs

ORDER = {
    "spec": "refund-facts/1",
    "order_id": "ORD-1",
    "customer_id": "C-1",
    "amount": 5000,
    "paid_with": "a@upi",
    "refunds": [{"amount": 1000}],
    "customer_refunds_today": 2,
    "customer_amount_today": 7000,
}
MODE = {"value": "ok"}


class _Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        mode = MODE["value"]
        if mode == "slow":
            time.sleep(1.5)
        if mode == "500":
            self.send_response(500)
            self.end_headers()
            return
        if self.path != "/v1/orders/ORD-1/refund-facts":
            self.send_response(404)
            self.end_headers()
            return
        body = {
            "ok": json.dumps(ORDER),
            "slow": json.dumps(ORDER),
            "garbage": "not json",
            "wrong-spec": json.dumps({**ORDER, "spec": "x"}),
            "wrong-order": json.dumps({**ORDER, "order_id": "ORD-2"}),
        }[mode].encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class _QuietServer(ThreadingHTTPServer):
    """The "slow" stub answers after the client's 1 s timeout has closed the
    socket. That broken pipe is the scenario under test, so it is not
    reported; any other server error still is."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


@pytest.fixture(scope="module")
def url():
    server = _QuietServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _source(url, **kw):
    return fs.FactSource(
        **{
            "operation": "POST /v1/refunds",
            "kind": fs.KIND_REFUND,
            "url": url,
            "timeout_seconds": 1.0,
            "verify": fs.REFUND_FACTS,
            **kw,
        }
    )


def test_config():
    raw = '{"POST /v1/refunds": {"kind": "refund-facts/1", "url": "https://pay.example/", "verify": ["customer_id"]}}'
    [source] = fs.sources_from_env({fs.SOURCES_ENV: raw}).values()
    assert (source.url, source.verify, source.timeout_seconds) == (
        "https://pay.example",
        ("customer_id",),
        2.0,
    )
    assert fs.sources_from_env({}) == {}


@pytest.mark.parametrize(
    "raw",
    [
        "x",
        "{}",
        '{"GET /r": {"kind": "refund-facts/1", "url": "http://h"}}',
        '{"POST /r": {"kind": "other", "url": "http://h"}}',
        '{"POST /r": {"kind": "refund-facts/1", "url": "ftp://h"}}',
        '{"POST /r": {"kind": "refund-facts/1", "url": "http://h", "timeout_seconds": 0}}',
        '{"POST /r": {"kind": "refund-facts/1", "url": "http://h", "verify": ["balance"]}}',
        '{"POST /r": {"kind": "refund-facts/1", "url": "http://h", "extra": 1}}',
    ],
)
def test_bad_config_refuses(raw):
    with pytest.raises(fs.FactSourceConfigError):
        fs.sources_from_env({fs.SOURCES_ENV: raw})


def test_derive():
    assert fs.derive_refund_facts(ORDER, 6000, "b@upi") == {
        "customer_id": "C-1",
        "original_amount": 5000,
        "original_payee": "a@upi",
        "amount_exceeds_original": True,
        "payee_matches_original": False,
        "prior_refunds_for_order": 1,
        "customer_refunds_today": 2,
        "customer_amount_today_after": 13000,
    }


HONEST = {
    "order_id": "ORD-1",
    "amount": 4000,
    "payee": "a@upi",
    **fs.derive_refund_facts(ORDER, 4000, "a@upi"),
}


@pytest.mark.parametrize(
    "change, expect",
    [
        ({}, None),
        (
            {"prior_refunds_for_order": 0},
            "prior_refunds_for_order: stated 0, system of record 1",
        ),
        ({"customer_id": "C-2"}, "customer_id"),
        (
            {"customer_refunds_today": True},
            "customer_refunds_today",
        ),  # True is not 1... nor 2
        ({"payee_matches_original": 1}, "payee_matches_original"),  # 1 is not True
        ({"amount": 4000.0}, fs.FACTS_INPUT_MISSING),
        ({"order_id": ""}, fs.FACTS_INPUT_MISSING),
    ],
)
def test_check(url, change, expect):
    MODE["value"] = "ok"
    args = {**HONEST, **change}
    finding = fs.check_facts(_source(url), args)
    if expect is None:
        assert finding is None
    else:
        assert finding is not None and (
            expect in finding.detail or expect == finding.code
        ), finding
    missing = {k: v for k, v in HONEST.items() if k != "customer_amount_today_after"}
    assert fs.check_facts(_source(url), missing).code == fs.FACTS_MISMATCH
    assert fs.check_facts(_source(url, verify=("customer_id",)), missing) is None


@pytest.mark.parametrize(
    "mode, code",
    [
        ("garbage", fs.FACTS_UNAVAILABLE),
        ("wrong-spec", fs.FACTS_UNAVAILABLE),
        ("wrong-order", fs.FACTS_UNAVAILABLE),
        ("500", fs.FACTS_UNAVAILABLE),
        ("slow", fs.FACTS_UNAVAILABLE),
    ],
)
def test_unreadable(url, mode, code):
    MODE["value"] = mode
    try:
        assert fs.check_facts(_source(url), HONEST).code == code
    finally:
        MODE["value"] = "ok"
    unknown = {**HONEST, "order_id": "ORD-404"}
    assert fs.check_facts(_source(url), unknown).code == fs.FACTS_ORDER_UNKNOWN
    assert (
        fs.check_facts(_source("http://127.0.0.1:9"), HONEST).code
        == fs.FACTS_UNAVAILABLE
    )
