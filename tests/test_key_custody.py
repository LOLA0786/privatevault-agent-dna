"""Signing keys in a KMS: same signatures, every one verified, failures closed.

Ed25519 is deterministic, so a KMS-held key must produce byte-for-byte the
signature the same key produces locally; verifiers cannot tell the
difference. Requests to AWS are checked against AWS's published API model
(tests/kms_fakes.py). The live check against a real key is
tools/kms_smoke.py.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    encode_public_key,
    sign_document,
    verify_document_signature,
)
from agent_dna.key_custody import (
    AWS_MAX_RAW_MESSAGE,
    AwsKmsSigner,
    GcpKmsSigner,
    LocalSigner,
    SignerError,
    kms_signer,
    signer_from_hex_seed,
    signer_from_seed_file,
)
from agent_dna.signer_python import ReceiptSigner, verify_envelope
from tests.kms_fakes import FakeAwsKms, FakeGcpKms, _Algorithm

pytest.importorskip("botocore")

DOC = {"spec": "test/0.1", "amount": 400000, "payee": "B-2002", "note": "x" * 200}


@pytest.fixture(params=["aws", "gcp"])
def kms(request):
    key = SigningKey.generate()
    if request.param == "aws":
        fake = FakeAwsKms(key=key)
        return key, fake, AwsKmsSigner(fake.key_id, client=fake)
    fake = FakeGcpKms(key=key)
    return key, fake, GcpKmsSigner(fake.name, client=fake)


def test_kms_signature_is_identical_to_the_local_one(kms):
    key, _, signer = kms
    assert signer.public_key == bytes(key.verify_key)
    remote = sign_document(DOC, signer, signature_field="signature")
    local = sign_document(DOC, key, signature_field="signature")
    assert remote == local  # deterministic Ed25519: verifiers cannot tell
    assert encode_public_key(signer) == encode_public_key(key)


def test_aws_requests_are_pure_ed25519_on_raw_bytes():
    fake = FakeAwsKms()
    signer = AwsKmsSigner(fake.key_id, client=fake)
    signer.sign(b"payload")
    operation, params = fake.calls[-1]
    assert operation == "Sign"
    assert params["MessageType"] == "RAW"
    assert params["SigningAlgorithm"] == "ED25519_SHA_512"  # never the _PH_ variant


def test_aws_refuses_documents_over_its_raw_limit_instead_of_prehashing():
    fake = FakeAwsKms()
    signer = AwsKmsSigner(fake.key_id, client=fake)
    with pytest.raises(SignerError, match="4096"):
        signer.sign(b"x" * (AWS_MAX_RAW_MESSAGE + 1))
    assert [op for op, _ in fake.calls] == ["GetPublicKey"]  # nothing sent
    assert len(signer.sign(b"x" * AWS_MAX_RAW_MESSAGE)) == 64


def test_a_kms_signature_that_does_not_verify_is_refused():
    fake = FakeAwsKms(tamper=True)  # e.g. wrong key, algorithm or proxy
    with pytest.raises(SignerError, match="does not verify"):
        AwsKmsSigner(fake.key_id, client=fake).sign(b"payload")


def test_wrong_key_types_are_refused_at_startup():
    with pytest.raises(SignerError, match="ECC_NIST_EDWARDS25519"):
        AwsKmsSigner("k", client=FakeAwsKms(key_spec="ECC_NIST_P256"))
    with pytest.raises(SignerError, match="EC_SIGN_ED25519"):
        GcpKmsSigner(
            FakeGcpKms().name,
            client=FakeGcpKms(algorithm=_Algorithm.EC_SIGN_P256_SHA256),
        )
    with pytest.raises(SignerError, match="key version"):
        GcpKmsSigner(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k", client=FakeGcpKms()
        )


def test_kms_outage_and_integrity_failures_raise_signer_error():
    with pytest.raises(SignerError, match="unreachable|failed"):
        AwsKmsSigner("k", client=FakeAwsKms(fail_sign=True)).sign(b"m")
    gcp = FakeGcpKms(corrupt_signature_crc=True)
    with pytest.raises(SignerError, match="CRC32C"):
        GcpKmsSigner(gcp.name, client=gcp).sign(b"m")
    gcp = FakeGcpKms(skip_data_check=True)
    with pytest.raises(SignerError, match="did not confirm"):
        GcpKmsSigner(gcp.name, client=gcp).sign(b"m")


def test_references_and_local_keys(tmp_path):
    fake = FakeAwsKms()
    assert isinstance(
        kms_signer(f"awskms:{fake.key_id}", clients={"aws": fake}), AwsKmsSigner
    )
    seed = SigningKey.generate()
    path = tmp_path / "exec.key"
    path.write_bytes(bytes(seed))
    assert signer_from_seed_file(str(path)).public_key == bytes(seed.verify_key)
    assert isinstance(signer_from_hex_seed(seed.encode().hex()), LocalSigner)
    with pytest.raises(SignerError):
        signer_from_seed_file(str(tmp_path / "missing.key"))
    with pytest.raises(SignerError):
        signer_from_hex_seed("not-hex")


def test_decision_receipts_signed_in_kms_verify(kms):
    key, _, signer = kms
    receipts = ReceiptSigner(signer=signer, key_id="kms-receipts")
    envelope = receipts.sign_hash("ab" * 32)
    assert envelope.public_key == bytes(key.verify_key).hex()
    assert verify_envelope(envelope.to_dict(), "ab" * 32)
    assert (
        envelope.signature
        == ReceiptSigner(seed_hex=key.encode().hex()).sign_hash("ab" * 32).signature
    )


def test_verified_document_from_kms(kms):
    _, _, signer = kms
    signed = sign_document(DOC, signer, signature_field="signature")
    assert verify_document_signature(
        signed, signature_field="signature", public_key=encode_public_key(signer)
    )


def test_smoke_tool_reports_a_working_key(monkeypatch, capsys):
    import json
    import sys
    from pathlib import Path

    boto3 = pytest.importorskip("boto3")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import kms_smoke

    fake = FakeAwsKms()
    monkeypatch.setattr(boto3, "client", lambda service, **_: fake)
    assert kms_smoke.main([f"awskms:{fake.key_id}"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["public_key_hex"] == bytes(fake.key.verify_key).hex()
    broken = FakeAwsKms(tamper=True)
    monkeypatch.setattr(boto3, "client", lambda service, **_: broken)
    assert kms_smoke.main([f"awskms:{broken.key_id}"]) == 1
    assert kms_smoke.main(["/not/a/kms/ref"]) == 2


def test_receiver_kit_receipt_key_in_kms(monkeypatch, tmp_path):
    boto3 = pytest.importorskip("boto3")
    from network.receiver_kit import config
    from tests.network.test_receiver_kit import _env

    fake = FakeAwsKms()
    monkeypatch.setattr(boto3, "client", lambda service, **_: fake)
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate())
    env["PV_RECEIPT_KEY_FILE"] = f"awskms:{fake.key_id}"
    gate = config.build_gate(config.settings_from_env(env))
    assert gate.receipt_public_key == encode_public_key(fake.key)
