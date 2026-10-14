"""Mint-side exact-byte binding (security review 2026-10).

1. A permit can never claim a human approval that did not happen.
2. Customer policy can see the sealed destination / METHOD+path / resource
   (evidence.bound), and callers cannot forge that key.
3. A same-origin HTTPS redirect does not permanently retarget the gateway.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from agent_dna.authorize_binding import AUTHORIZE_APPROVAL_MISMATCH
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.errors import SameOriginRedirectError
from agent_dna.gateway.https_egress import dispatch_https_egress
from agent_dna.gateway.session import new_session_id
from tests.decide_binding import decide_json, dispatch_context_for
from tests.gateway import conftest as gateway_conftest
from tests.gateway.conftest import agent_key, allow_runtime, credentials  # noqa: F401
from tests.test_wire_action_binding import (  # noqa: F401
    AGENT,
    ARGS40,
    CAP,
    ORG,
    WIRE40,
    _authorize,
    env,
)

FAKE = "sha256:" + "ab" * 32
GOOD_OP = "POST /v1/purchase-orders"
EVIL_OP = "DELETE /v1/admin/accounts/all"


def _decide(client, key, *, operation=GOOD_OP, **extra):
    return client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS40),
            resource="erp-sandbox.example",
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation=operation, destination="erp-sandbox.example"
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(WIRE40),
            expected_wire_bytes_length=len(WIRE40),
            **extra,
        ),
    )


# ---- 1. no fake approval claims ----------------------------------------


def test_fake_approval_digest_refused_on_non_approval_allow(env):  # noqa: F811
    client, key = env["client"], env["key"]
    decided = _decide(client, key)
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]

    original = client.post

    def _with_fake_approval(url, headers=None, json=None):  # noqa: A002
        if url == "/v1/authorize":
            json = dict(json, approval_artifact_digest=FAKE)
        return original(url, headers=headers, json=json)

    client.post = _with_fake_approval
    try:
        refused = _authorize(client, key, record)
    finally:
        client.post = original
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason_code"] == AUTHORIZE_APPROVAL_MISMATCH

    minted = _authorize(client, key, record)
    assert minted.status_code == 200, minted.text
    assert minted.json()["authorization"]["approval_artifact_digest"] is None


def test_zero_placeholder_still_means_no_approval(env):  # noqa: F811
    """Shipped partner/receiver kits send the all-zero digest for 'none'."""
    client, key = env["client"], env["key"]
    record = _decide(client, key).json()["record"]
    original = client.post

    def _with_zero(url, headers=None, json=None):  # noqa: A002
        if url == "/v1/authorize":
            json = dict(json, approval_artifact_digest="sha256:" + "0" * 64)
        return original(url, headers=headers, json=json)

    client.post = _with_zero
    try:
        minted = _authorize(client, key, record)
    finally:
        client.post = original
    assert minted.status_code == 200, minted.text


# ---- 2. policy sees the sealed dispatch --------------------------------


@pytest.fixture()
def policy_env(tmp_path, monkeypatch, request):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "only-po-create",
                        "capability": CAP,
                        "outcome": "block",
                        "reason": "only POST /v1/purchase-orders is allowed",
                        "condition": {
                            "field": "evidence.bound.operation",
                            "operator": "not_in",
                            "value": [GOOD_OP],
                        },
                    }
                ]
            }
        )
    )
    monkeypatch.setenv("PV_POLICY_FILE", str(policy))
    return request.getfixturevalue("env")


def test_policy_can_block_on_sealed_operation(policy_env):
    client, key = policy_env["client"], policy_env["key"]
    ok = _decide(client, key, operation=GOOD_OP)
    assert ok.status_code == 200, ok.text
    bad = _decide(client, key, operation=EVIL_OP)
    assert bad.status_code == 403, bad.text
    assert bad.json()["triggered_by"] == "policy"


def test_caller_cannot_forge_bound_evidence(policy_env):
    client, key = policy_env["client"], policy_env["key"]
    forged = _decide(
        client,
        key,
        operation=EVIL_OP,
        evidence={"bound": {"operation": GOOD_OP}},
    )
    # sealed values overwrite the caller's copy, so the rule still fires
    assert forged.status_code == 403, forged.text


# ---- 3. redirect does not retarget the gateway -------------------------


@dataclass
class _RedirectOnceHttps:
    url: str = "https://saas.example/v1/payments"
    identity: str = "https-egress://test"
    writes: list[bytes] = field(default_factory=list)
    last_body: bytes = b'{"ok":true}'
    session_id: str = ""
    _redirected: bool = False

    def bind_session(self, session_id: str) -> None:
        self.session_id = session_id

    def write(self, wire_bytes: bytes) -> None:
        self.writes.append(wire_bytes)
        if not self._redirected:
            self._redirected = True
            raise SameOriginRedirectError("https://saas.example/v1/admin/purge")


def test_redirect_does_not_retarget_named_url(allow_runtime, credentials):  # noqa: F811
    rt, key = allow_runtime
    upstream = _RedirectOnceHttps()
    named, identity = upstream.url, upstream.identity
    dispatch_https_egress(
        middleware=rt.middleware(),
        upstream=upstream,
        credentials=credentials,
        agent_api_key=key,
        session_id=new_session_id(),
        client_identity="gateway-agent@test",
        capability=gateway_conftest.TOOL,
        method="POST",
        url=named,
        body=b"{}",
    )
    assert len(upstream.writes) == 2  # original hop + one re-decided hop
    assert upstream.url == named
    assert upstream.identity == identity
