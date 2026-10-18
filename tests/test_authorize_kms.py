"""/v1/authorize with the execution signer in a KMS (awskms: reference).

The permit a KMS key signs is the permit the local key would sign; a key the
trust bundle does not pin is refused before any permit exists; a KMS outage
refuses the mint (503) without stranding the decision, which mints once the
KMS is back.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import encode_public_key, verify_document_signature
from agent_dna.authorize_binding import AUTHORIZE_SIGNER_UNAVAILABLE
from tests.kms_fakes import FakeAwsKms
from tests.test_grant_revocation import _decide
from tests.test_wire_action_binding import _authorize, env  # noqa: F401

boto3 = pytest.importorskip("boto3")


def _use_kms(monkeypatch, server, fake):
    monkeypatch.setattr(boto3, "client", lambda service, **_: fake)
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", f"awskms:{fake.key_id}")
    server._pv_signer_cache.clear()


def _pinned_key(tmp_path) -> SigningKey:
    return SigningKey((tmp_path / "exec.key").read_bytes())


def test_permit_is_signed_in_kms_and_verifies(env, tmp_path, monkeypatch):  # noqa: F811
    key = _pinned_key(tmp_path)
    fake = FakeAwsKms(key=key)
    _use_kms(monkeypatch, env["server"], fake)
    record = _decide(env["client"], env["key"])
    r = _authorize(env["client"], env["key"], record)
    assert r.status_code == 200, r.text
    permit = r.json()["authorization"]
    assert verify_document_signature(
        permit, signature_field="signature", public_key=encode_public_key(key)
    )
    assert [op for op, _ in fake.calls].count("Sign") == 1
    revocations = env["client"].get(
        "/v1/revocations", headers={"X-API-Key": env["key"]}
    )
    assert revocations.status_code == 200, revocations.text
    assert verify_document_signature(
        revocations.json(),
        signature_field="signature",
        public_key=encode_public_key(key),
    )


def test_a_kms_key_the_bundle_does_not_pin_is_refused(env, monkeypatch):  # noqa: F811
    _use_kms(monkeypatch, env["server"], FakeAwsKms())  # some other key
    record = _decide(env["client"], env["key"])
    r = _authorize(env["client"], env["key"], record)
    assert r.status_code == 503 and "not pinned" in r.text


def test_kms_outage_refuses_then_recovers(env, tmp_path, monkeypatch):  # noqa: F811
    fake = FakeAwsKms(key=_pinned_key(tmp_path), fail_sign=True)
    _use_kms(monkeypatch, env["server"], fake)
    record = _decide(env["client"], env["key"])
    down = _authorize(env["client"], env["key"], record)
    assert down.status_code == 503, down.text
    assert down.json()["detail"]["reason_code"] == AUTHORIZE_SIGNER_UNAVAILABLE
    fake.fail_sign = False
    up = _authorize(env["client"], env["key"], record)
    assert up.status_code == 200, up.text  # the failed attempt left no claim
