"""Receiver kit: a partner-operated gate refuses altered and replayed actions.

Claims -> tests:
  - Missing or malformed configuration refuses to start
    -> test_config_refuses_missing_var, test_config_refuses_malformed
  - A receipt key that is also an issuer key refuses to start
    -> test_receipt_key_must_be_independent
  - Gate and issuer derive the same trust bundle digest from the same env,
    whatever the key order
    -> test_trust_bundle_is_deterministic
  - keygen writes a 0600 private key and never overwrites
    -> test_keygen_cli
  - send_test's three steps: valid permit admitted once with exact bytes and
    no permit header forwarded; amount changed refused; replay refused
    -> test_send_test_flow
  - Fresh permit from an unknown key, wrong audience, expired, or no permit:
    refused, upstream untouched
    -> test_adversarial_permits_never_reach_upstream
  - Exported receipts pass the independent verifier with the partner's key in
    an isolated interpreter; a tampered receipt fails
    -> test_export_and_independent_verifier
  - send_test exit code is 0 only when every step passes
    -> test_exit_code
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import encode_public_key, sha256_digest
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from network.receiver_kit import config, export_receipts, keygen, send_test, upstream

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


RECEIVER = "payments.partner.example"
DESTINATION = "https://payments.partner.example"
ORG = "lender.example"


def _env(
    tmp_path: Path, issuer: SigningKey, receipt: SigningKey, **over: str
) -> dict[str, str]:
    key_file = tmp_path / "receiver.key"
    if not key_file.exists():
        keygen.write_key(receipt, key_file)
    env = {
        "PV_RECEIVER_ID": RECEIVER,
        "PV_RECEIVER_DESTINATIONS": DESTINATION,
        "PV_ISSUER_ORGANISATION": ORG,
        "PV_ISSUER_KEYS": f"ea-signer={encode_public_key(issuer)}",
        "PV_RECEIPT_KEY_FILE": str(key_file),
        "PV_RECEIPT_KEY_ID": "partner-receiver-01",
        "PV_UPSTREAM": "http://127.0.0.1:1",
        "PV_ALLOW_HTTP_UPSTREAM": "1",
        "PV_LEDGER_PATH": str(tmp_path / "receiver.db"),
    }
    env.update(over)
    return env


def _issuer(
    env: Mapping[str, str], signer: SigningKey, key_id: str = "ea-signer"
) -> send_test.Issuer:
    return send_test.Issuer(
        signing_key=signer,
        key_id=key_id,
        organisation_id=env["PV_ISSUER_ORGANISATION"],
        bundle=config.trust_bundle(
            env["PV_ISSUER_ORGANISATION"],
            config.parse_issuer_keys(env["PV_ISSUER_KEYS"]),
        ),
        receiver_id=env["PV_RECEIVER_ID"],
        destination=env["PV_RECEIVER_DESTINATIONS"],
    )


class _World:
    """Gate proxy under an in-process httpx client, real threaded upstream."""

    def __init__(self, tmp_path: Path) -> None:
        self.issuer_key = SigningKey.generate()
        self.receipt_key = SigningKey.generate()
        self.upstream = upstream.start()
        self.env = _env(
            tmp_path,
            self.issuer_key,
            self.receipt_key,
            PV_UPSTREAM=f"http://127.0.0.1:{self.upstream.port}",
        )
        self.settings = config.settings_from_env(self.env)
        self.app = config.build_app(self.settings)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://gate"
        )
        self.issuer = _issuer(self.env, self.issuer_key)

    async def send(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        resp = await self.client.request(
            method, path, headers=dict(headers), content=body
        )
        return resp.status_code, dict(resp.headers), resp.content

    def seen(self) -> list[dict[str, Any]]:
        return self.upstream.seen()


def _sync_sender(world: _World) -> send_test.Sender:
    """A synchronous Sender for send_test.run, backed by the in-process app.

    Each call runs its own short event loop, so this must be used from a
    synchronous test (not inside a running loop).
    """

    def send(
        method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        async def go() -> tuple[int, Mapping[str, str], bytes]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=world.app), base_url="http://gate"
            ) as client:
                resp = await client.request(
                    method, path, headers=dict(headers), content=body
                )
                return resp.status_code, dict(resp.headers), resp.content

        return anyio.run(go)

    return send


def _sync_run(world: _World) -> list[send_test.Step]:
    return send_test.run(world.issuer, _sync_sender(world), world.seen)


# ------------------------------------------------------------------ config


@pytest.mark.parametrize("missing", config.REQUIRED_VARS)
def test_config_refuses_missing_var(tmp_path, missing):
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate())
    env.pop(missing)
    with pytest.raises(config.ConfigError, match=missing):
        config.settings_from_env(env)


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"PV_ISSUER_KEYS": "ea-signer=not-base64!"}, "not valid base64"),
        ({"PV_ISSUER_KEYS": "ea-signer=AAAA"}, "32 bytes"),
        ({"PV_ISSUER_KEYS": "no-equals-sign"}, "key_id=BASE64"),
        ({"PV_ALLOW_HTTP_UPSTREAM": "maybe"}, "0 or 1"),
        ({"PV_TRUST_BUNDLE_VERSION": "0"}, ">= 1"),
        ({"PV_RECEIVER_DESTINATIONS": "a;a"}, "duplicate"),
    ],
)
def test_config_refuses_malformed(tmp_path, override, match):
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate(), **override)
    with pytest.raises(config.ConfigError, match=match):
        config.settings_from_env(env)


def test_config_refuses_duplicate_issuer_key_id(tmp_path):
    a, b = SigningKey.generate(), SigningKey.generate()
    env = _env(
        tmp_path,
        a,
        SigningKey.generate(),
        PV_ISSUER_KEYS=f"ea-signer={encode_public_key(a)};ea-signer={encode_public_key(b)}",
    )
    with pytest.raises(config.ConfigError, match="duplicate key_id"):
        config.settings_from_env(env)


def test_receipt_key_must_be_independent(tmp_path):
    shared = SigningKey.generate()
    env = _env(tmp_path, shared, shared)
    with pytest.raises(ValueError, match="independent key"):
        config.build_gate(config.settings_from_env(env))


def test_group_readable_key_file_refused(tmp_path):
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate())
    Path(env["PV_RECEIPT_KEY_FILE"]).chmod(0o640)
    with pytest.raises(config.ConfigError, match="chmod 600"):
        config.build_gate(config.settings_from_env(env))


def test_unprotected_write_route_refused(tmp_path):
    env = _env(
        tmp_path,
        SigningKey.generate(),
        SigningKey.generate(),
        PV_UNPROTECTED_OPERATIONS="POST /anything",
    )
    with pytest.raises(ValueError, match="only GET/HEAD"):
        config.build_gate(config.settings_from_env(env))


def test_trust_bundle_is_deterministic():
    a, b = SigningKey.generate(), SigningKey.generate()
    one = config.parse_issuer_keys(
        f"k1={encode_public_key(a)};k2={encode_public_key(b)}"
    )
    two = config.parse_issuer_keys(
        f"k2={encode_public_key(b)};k1={encode_public_key(a)}"
    )
    assert sha256_digest(config.trust_bundle(ORG, one)) == sha256_digest(
        config.trust_bundle(ORG, two)
    )
    # A different pinned_at is a different bundle; a permit naming one is
    # refused by a gate pinning the other.
    assert sha256_digest(config.trust_bundle(ORG, one)) != sha256_digest(
        config.trust_bundle(ORG, one, pinned_at="2026-02-01T00:00:00Z")
    )


# ------------------------------------------------------------------ keygen


def test_keygen_cli(tmp_path):
    out = tmp_path / "keys"
    cmd = [
        sys.executable,
        "-m",
        "network.receiver_kit.keygen",
        "receiver",
        "--out",
        str(out),
    ]
    first = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    key, pub = out / "receiver.key", out / "receiver.pub"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert pub.read_text().strip() in first.stdout
    assert key.read_text().strip() not in first.stdout
    loaded = config.load_signing_key(key)
    assert encode_public_key(loaded) == pub.read_text().strip()

    before = key.read_bytes()
    second = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, check=False)
    assert second.returncode == 1
    assert "not overwriting" in second.stderr
    assert key.read_bytes() == before


# -------------------------------------------------------------------- flow


async def test_send_test_flow(tmp_path):
    w = _World(tmp_path)
    permit, wire = send_test.mint_permit(w.issuer, send_test.PARAMETERS)
    headers = {
        "Content-Type": "application/json",
        PERMIT_HEADER: encode_permit_header(permit),
    }
    tampered = send_test.serialize_parameters_wire(
        send_test.TAMPERED, serialization=send_test.SERIALIZATION
    )

    status, resp_headers, _ = await w.send("POST", send_test.PATH, headers, wire)
    assert status == 200
    assert "x-pv-receiver-receipt" in resp_headers
    seen = w.seen()
    assert len(seen) == 1
    assert seen[0]["body_sha256"] == "sha256:" + hashlib.sha256(wire).hexdigest()
    assert seen[0]["body_length"] == len(wire)
    assert PERMIT_HEADER.lower() not in seen[0]["header_names"]

    status, _, body = await w.send("POST", send_test.PATH, headers, tampered)
    assert status == 403
    assert json.loads(body)["reason_code"] == "RECEIVER_WIRE_MISMATCH"
    assert len(w.seen()) == 1

    status, _, body = await w.send("POST", send_test.PATH, headers, wire)
    assert status == 409
    assert json.loads(body)["reason_code"] == "RECEIVER_PERMIT_CONSUMED"
    assert len(w.seen()) == 1

    receipts = list(w.app.gate.ledger.iter_receipts())
    assert [r["outcome"] for r in receipts] == ["ADMITTED", "REFUSED", "REFUSED"]
    assert [r["reason_code"] for r in receipts] == [
        None,
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_PERMIT_CONSUMED",
    ]


def test_send_test_run_reports_all_pass(tmp_path):
    """The real send_test.run, unmodified, against the in-process gate."""
    w = _World(tmp_path)
    steps = _sync_run(w)
    assert send_test.exit_code(steps) == 0, send_test.report(steps)
    assert [s.name for s in steps] == ["valid permit", "amount changed", "replay"]
    assert "ALL PASS" in send_test.report(steps)
    assert [s.upstream_after - s.upstream_before for s in steps] == [1, 0, 0]


async def test_adversarial_permits_never_reach_upstream(tmp_path):
    w = _World(tmp_path)
    wire = send_test.serialize_parameters_wire(
        send_test.TAMPERED, serialization=send_test.SERIALIZATION
    )

    # Fresh, well-formed permit for the altered amount, signed by a key the
    # receiver never pinned.
    rogue = _issuer(w.env, SigningKey.generate(), key_id="ea-signer")
    permit, _ = send_test.mint_permit(rogue, send_test.TAMPERED)
    status, _, body = await w.send(
        "POST", send_test.PATH, {PERMIT_HEADER: encode_permit_header(permit)}, wire
    )
    assert (status, json.loads(body)["reason_code"]) == (
        403,
        "RECEIVER_PERMIT_SIGNATURE_INVALID",
    )

    unknown = _issuer(w.env, SigningKey.generate(), key_id="someone-else")
    permit, _ = send_test.mint_permit(unknown, send_test.TAMPERED)
    status, _, body = await w.send(
        "POST", send_test.PATH, {PERMIT_HEADER: encode_permit_header(permit)}, wire
    )
    assert (status, json.loads(body)["reason_code"]) == (
        403,
        "RECEIVER_TRUST_ROOT_UNKNOWN",
    )

    # Right key, wrong receiver.
    other = send_test.Issuer(
        **{**w.issuer.__dict__, "receiver_id": "other.partner.example"}
    )
    permit, good_wire = send_test.mint_permit(other, send_test.PARAMETERS)
    status, _, body = await w.send(
        "POST", send_test.PATH, {PERMIT_HEADER: encode_permit_header(permit)}, good_wire
    )
    assert (status, json.loads(body)["reason_code"]) == (
        403,
        "RECEIVER_AUDIENCE_MISMATCH",
    )

    # Expired.
    permit, good_wire = send_test.mint_permit(
        w.issuer, send_test.PARAMETERS, now=datetime.now(UTC) - timedelta(minutes=5)
    )
    status, _, body = await w.send(
        "POST", send_test.PATH, {PERMIT_HEADER: encode_permit_header(permit)}, good_wire
    )
    assert (status, json.loads(body)["reason_code"]) == (403, "RECEIVER_PERMIT_EXPIRED")

    # No permit at all (the direct-call bypass).
    status, _, body = await w.send("POST", send_test.PATH, {}, good_wire)
    assert (status, json.loads(body)["reason_code"]) == (403, "RECEIVER_PERMIT_MISSING")

    assert w.seen() == []
    assert all(r["outcome"] == "REFUSED" for r in w.app.gate.ledger.iter_receipts())


# ------------------------------------------------------------ verification


def test_export_and_independent_verifier(tmp_path):
    w = _World(tmp_path)
    steps = _sync_run(w)
    assert send_test.exit_code(steps) == 0, send_test.report(steps)

    out = tmp_path / "receipts.jsonl"
    assert export_receipts.export(w.settings.ledger_path, out) == 3
    lines = out.read_text().splitlines()
    assert len(lines) == 3

    public = w.app.gate.receipt_public_key
    base = [
        sys.executable,
        "-I",
        str(VERIFIER),
        "--receiver-id",
        RECEIVER,
        "--receiver-key",
        f"partner-receiver-01={public}",
    ]
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH"}}
    ok = subprocess.run(
        [*base, "--jsonl", str(out)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert ok.stdout.startswith(
        "OK 3 receipts (1 admitted, 2 refused), mode=chain+signatures"
    )

    from_db = subprocess.run(
        [*base, "--db", str(w.settings.ledger_path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert from_db.returncode == 0, from_db.stdout + from_db.stderr

    # Another operator's key does not verify these receipts.
    wrong = subprocess.run(
        [
            *base[:-1],
            f"partner-receiver-01={encode_public_key(SigningKey.generate())}",
            "--jsonl",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert wrong.returncode == 1
    assert "signature invalid" in wrong.stdout

    # A tampered receipt (refusal rewritten as admission) breaks the chain.
    records = [json.loads(line) for line in lines]
    records[1]["outcome"] = "ADMITTED"
    records[1]["reason_code"] = None
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    bad = subprocess.run(
        [*base, "--jsonl", str(tampered)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert bad.returncode == 1
    assert "FAIL" in bad.stdout


def test_exit_code():
    good = send_test.Step(
        "x", 200, None, status=200, expect_upstream_delta=1, upstream_after=1
    )
    bad = send_test.Step("y", 403, "R", status=200)
    assert send_test.exit_code([good]) == 0
    assert send_test.exit_code([good, bad]) == 1
    assert send_test.exit_code([]) == 1
    assert "SOME FAILED" in send_test.report([good, bad])


def test_env_file_reader(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('# comment\nPV_A=1\nPV_B="quoted value"\nbroken line\n')
    assert send_test.read_env_file(env_file) == {"PV_A": "1", "PV_B": "quoted value"}
    assert send_test.read_env_file(tmp_path / "missing") == {}


@pytest.mark.skipif(
    subprocess.run(
        ["docker", "compose", "version"], capture_output=True, check=False
    ).returncode
    != 0,
    reason="docker compose not available",
)
def test_compose_file_is_valid():
    kit = REPO / "network" / "receiver_kit"
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(kit / "docker-compose.yml"),
            "config",
            "--quiet",
        ],
        cwd=kit,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
