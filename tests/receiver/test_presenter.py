"""Presenter binding (ADR 0022): only the agent's own TLS key can present its permit.

Claims -> tests:
  - The identity is the SPKI SHA-256 (RFC 7469 pin-sha256), matching openssl
    and `cryptography` -> test_identity_matches_openssl_and_cryptography
  - Re-issuing a certificate for the same key keeps the identity
    -> test_reissued_certificate_keeps_identity
  - Permit spec 0.2 carries exactly one more signed field
    -> test_permit_v02_fields
  - The gate admits the bound presenter, refuses another key, no key, and
    (when required) a permit that binds none; a refused presenter does not
    burn the permit -> test_gate_*
  - Altering the bound presenter breaks the permit signature
    -> test_rebinding_the_presenter_breaks_the_signature
"""

from __future__ import annotations

import copy
import hashlib
import subprocess

import pytest

from agent_dna.authority_v01 import AuthorityFormatError
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    EXECUTION_AUTHORIZATION_SPEC_V02,
    bound_presenter_digest,
    validate_execution_authorization,
)
from agent_dna.presenter_identity import (
    PresenterIdentityError,
    certificate_der_from_file,
    presenter_identity_digest,
    spki_from_certificate_der,
    validate_presenter_bundle,
)
from agent_dna.receiver import gate as g
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header

from ._pki import Pki
from ._world import METHOD, NOW, PARAMETERS, PATH, World, wire_for


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    p = Pki(tmp_path_factory.mktemp("pki"))
    return p, p.leaf("agent-a"), p.leaf("agent-b")


def _digest(leaf) -> str:
    return presenter_identity_digest(certificate_der_from_file(leaf.cert))


def _send(world, permit, presenter_cert=None):
    return world.gate.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, encode_permit_header(permit))],
        body=wire_for(PARAMETERS),
        received_at=NOW,
        presenter_certificate=presenter_cert,
    )


# ---- identity ----------------------------------------------------------------


def test_identity_matches_openssl_and_cryptography(pki):
    _, a, _ = pki
    der = certificate_der_from_file(a.cert)
    pubkey = subprocess.run(
        ["openssl", "x509", "-in", str(a.cert), "-pubkey", "-noout"],
        capture_output=True,
        check=True,
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "der"],
        input=pubkey,
        capture_output=True,
        check=True,
    ).stdout
    assert (
        presenter_identity_digest(der) == "sha256:" + hashlib.sha256(spki).hexdigest()
    )
    x509 = pytest.importorskip("cryptography.x509")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    reference = (
        x509.load_der_x509_certificate(der)
        .public_key()
        .public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert spki_from_certificate_der(der) == reference


def test_reissued_certificate_keeps_identity(pki):
    ca, a, b = pki
    again = ca.leaf("agent-a-renewed", key=a.key)
    assert certificate_der_from_file(again.cert) != certificate_der_from_file(a.cert)
    assert _digest(again) == _digest(a) != _digest(b)


@pytest.mark.parametrize(
    "bad", [b"", b"\x30\x03\x02\x01", b"\x30\x80\x00\x00", b"x" * 40]
)
def test_malformed_certificates_are_refused(bad):
    with pytest.raises(PresenterIdentityError):
        presenter_identity_digest(bad)


def test_presenter_bundle_validation():
    digest = "sha256:" + "a" * 64
    ok = validate_presenter_bundle(
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "o",
            "presenters": {"x": [digest]},
        }
    )
    assert ok.allowed("x") == {digest} and ok.allowed("y") == frozenset()
    for broken in (
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "o",
            "presenters": {"x": []},
        },
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "o",
            "presenters": {"x": ["md5:1"]},
        },
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "o",
            "presenters": {"x": [digest, digest]},
        },
        {
            "spec": "pv-presenter-bundle/0.2",
            "organisation_id": "o",
            "presenters": {"x": [digest]},
        },
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "",
            "presenters": {"x": [digest]},
        },
        {
            "spec": "pv-presenter-bundle/0.1",
            "organisation_id": "o",
            "presenters": {},
            "extra": 1,
        },
    ):
        with pytest.raises(PresenterIdentityError):
            validate_presenter_bundle(broken)


# ---- permit spec 0.2 ----------------------------------------------------------


def test_permit_v02_fields(tmp_path, pki):
    world = World(tmp_path)
    plain = world.permit()
    bound = world.permit(presenter=_digest(pki[1]))
    assert (
        plain["spec"] == EXECUTION_AUTHORIZATION_SPEC
        and bound_presenter_digest(plain) is None
    )
    assert bound["spec"] == EXECUTION_AUTHORIZATION_SPEC_V02
    assert set(bound) - set(plain) == {"expected_presenter_identity_digest"}
    assert bound_presenter_digest(validate_execution_authorization(bound)) == _digest(
        pki[1]
    )
    smuggled = dict(plain, expected_presenter_identity_digest=_digest(pki[1]))
    with pytest.raises(AuthorityFormatError, match="unexpected fields"):
        validate_execution_authorization(smuggled)  # 0.1 cannot carry it
    stripped = {
        k: v for k, v in bound.items() if k != "expected_presenter_identity_digest"
    }
    with pytest.raises(AuthorityFormatError, match="missing fields"):
        validate_execution_authorization(stripped)  # 0.2 must carry it


# ---- gate --------------------------------------------------------------------


def test_gate_admits_the_bound_presenter(tmp_path, pki):
    _, a, _ = pki
    world = World(tmp_path)
    decision = _send(
        world, world.permit(presenter=_digest(a)), certificate_der_from_file(a.cert)
    )
    assert decision.admitted, decision


def test_gate_refuses_another_key_without_burning_the_permit(tmp_path, pki):
    _, a, b = pki
    world = World(tmp_path)
    permit = world.permit(presenter=_digest(a))
    thief = _send(world, permit, certificate_der_from_file(b.cert))
    assert not thief.admitted and thief.reason_code == g.RECEIVER_PRESENTER_MISMATCH
    assert thief.receipt is not None  # the refusal is evidence too
    owner = _send(world, permit, certificate_der_from_file(a.cert))
    assert owner.admitted, owner  # the thief's attempt did not consume it
    again = _send(world, permit, certificate_der_from_file(a.cert))
    assert again.reason_code == g.RECEIVER_PERMIT_CONSUMED


def test_gate_refuses_a_bound_permit_without_a_client_certificate(tmp_path, pki):
    world = World(tmp_path)
    decision = _send(world, world.permit(presenter=_digest(pki[1])), None)
    assert decision.reason_code == g.RECEIVER_PRESENTER_MISSING


def test_gate_requiring_presenters_refuses_unbound_permits(tmp_path, pki):
    (tmp_path / "strict").mkdir()
    (tmp_path / "lenient").mkdir()
    strict = World(tmp_path / "strict", require_presenter=True)
    refused = _send(strict, strict.permit(), certificate_der_from_file(pki[1].cert))
    assert refused.reason_code == g.RECEIVER_PRESENTER_REQUIRED
    lenient = World(tmp_path / "lenient")
    assert _send(lenient, lenient.permit(), None).admitted  # 0.1 still accepted


def test_rebinding_the_presenter_breaks_the_signature(tmp_path, pki):
    _, a, b = pki
    world = World(tmp_path)
    permit = copy.deepcopy(world.permit(presenter=_digest(a)))
    permit["expected_presenter_identity_digest"] = _digest(b)  # thief edits it
    decision = _send(world, permit, certificate_der_from_file(b.cert))
    assert decision.reason_code == g.RECEIVER_PERMIT_SIGNATURE_INVALID


def test_v02_permit_matches_its_published_schema(tmp_path, pki):
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    from agent_dna import execution_v01

    path = Path("spec/execution-v01/execution-authorization-v02.schema.json")
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert set(schema["required"]) == set(execution_v01._AUTHORIZATION_FIELDS_V02)
    Draft202012Validator(schema).validate(
        World(tmp_path).permit(presenter=_digest(pki[1]))
    )
