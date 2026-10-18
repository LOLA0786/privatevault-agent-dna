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


def _docker_compose_available() -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, check=False
            ).returncode
            == 0
        )
    except OSError:  # no docker binary: skip, never abort collection
        return False


@pytest.mark.skipif(
    not _docker_compose_available(), reason="docker compose not available"
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


# ---- R1 #10: the key must reach the gate user on Linux, not only on macOS --

KIT = REPO / "network" / "receiver_kit"


def test_gate_does_not_depend_on_host_uid_matching_the_container_user():
    """On Linux a bind-mounted 0600 key keeps the host's uid, so a container
    running as a fixed non-root uid cannot read it (Docker Desktop on macOS
    remaps ownership and hides this). The kit must not rely on a `user:`
    override or on the host uid: the image starts an entrypoint that hands
    the key to the gate user and drops root, and the ledger lives in a named
    volume rather than a host directory."""
    import yaml

    compose = yaml.safe_load((KIT / "docker-compose.yml").read_text())
    gate = compose["services"]["gate"]
    assert "user" not in gate, "a uid override is not the mechanism"
    volumes = gate["volumes"]
    assert any(v.startswith("./keys:/keys:ro") for v in volumes)
    assert not any(v.startswith("./data") for v in volumes), "no host data dir"
    assert any(v.startswith("data:/data") for v in volumes)
    assert "data" in compose.get("volumes", {})
    assert "/run/pv" in gate.get("tmpfs", []), "key copy lives in tmpfs"

    dockerfile = (KIT / "Dockerfile").read_text()
    assert "ENTRYPOINT" in dockerfile and "entrypoint.sh" in dockerfile
    assert "\nUSER " not in dockerfile, "root at start; the entrypoint drops it"
    entrypoint = (KIT / "entrypoint.sh").read_text()
    assert "setpriv" in entrypoint and "--no-new-privs" in entrypoint
    assert stat.S_IMODE((KIT / "entrypoint.sh").stat().st_mode) & 0o111


def test_unreadable_key_file_error_is_actionable(tmp_path):
    """A key the gate user cannot read is a configuration error with
    guidance, not a bare PermissionError. Mode 0400, which the entrypoint
    installs, loads."""
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate())
    key = Path(env["PV_RECEIPT_KEY_FILE"])
    key.chmod(0)
    try:
        with pytest.raises(config.ConfigError, match="gate user .* cannot read"):
            config.build_gate(config.settings_from_env(env))
    finally:
        key.chmod(0o400)
    assert config.build_gate(config.settings_from_env(env)).receipt_public_key


@pytest.mark.skipif(
    os.environ.get("PV_KIT_DOCKER_TESTS") != "1",
    reason="set PV_KIT_DOCKER_TESTS=1 to build the image and run its entrypoint",
)
def test_entrypoint_hands_key_to_gate_user_and_drops_root(tmp_path):
    """Build the kit image, mount a host-owned 0600 key read-only, and check
    that the process runs as uid 10001 with a 0400 copy of the key it owns,
    while the mounted original is untouched."""
    image = "pv-receiver-kit-test"
    build = subprocess.run(
        [
            "docker",
            "build",
            "-q",
            "-f",
            str(KIT / "Dockerfile"),
            "-t",
            image,
            str(REPO),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    keys = tmp_path / "keys"
    keygen.write_key(SigningKey.generate(), keys / "receiver.key")
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--tmpfs",
            "/run/pv",
            "-v",
            f"{keys}:/keys:ro",
            "-e",
            "PV_RECEIPT_KEY_FILE=/keys/receiver.key",
            image,
            "sh",
            "-c",
            'id -u; echo "$PV_RECEIPT_KEY_FILE"; stat -c "%u:%a" "$PV_RECEIPT_KEY_FILE"; '
            "cat /proc/self/status | grep -E '^(CapEff|NoNewPrivs)'",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    uid, key_path, owner_mode, cap_eff, nnp = run.stdout.split("\n")[:5]
    assert uid == "10001"
    assert key_path == "/run/pv/receiver.key"
    assert owner_mode == "10001:400"
    assert cap_eff.split()[-1] == "0000000000000000", cap_eff
    assert nnp.split()[-1] == "1", nnp
    assert stat.S_IMODE((keys / "receiver.key").stat().st_mode) == 0o600


# ------------------------------------------------- pinned trust bundle file
#
# Claims -> tests:
#   - PV_TRUST_BUNDLE_FILE pins the file's bundle byte for byte, so the API,
#     sidecar and gate can share one bundle (signer plus witness keys); the
#     derived-bundle variables become optional
#     -> test_trust_bundle_file_is_pinned
#   - A bundle file that is not JSON, not a trust bundle, lacks a signer key,
#     names another organisation, or disagrees with PV_ISSUER_KEYS refuses to
#     start the gate
#     -> test_trust_bundle_file_refuses_malformed_or_mismatched


def _shared_bundle(signer: SigningKey, witness: SigningKey) -> dict[str, Any]:
    return {
        "spec": "pv-trust-bundle/0.1",
        "canonicalization": "rfc8785-json",
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-01-01T00:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(signer),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": f"egress-witness@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }


def test_trust_bundle_file_is_pinned(tmp_path):
    from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC

    signer, witness = SigningKey.generate(), SigningKey.generate()
    bundle = _shared_bundle(signer, witness)
    bundle["spec"], bundle["canonicalization"] = TRUST_SPEC, CANONICALIZATION
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(bundle))
    env = _env(tmp_path, signer, SigningKey.generate(), PV_TRUST_BUNDLE_FILE=str(path))
    env.pop("PV_ISSUER_ORGANISATION")
    env.pop("PV_ISSUER_KEYS")
    settings = config.settings_from_env(env)
    assert settings.trust_bundle == bundle
    assert settings.trust_bundle_digest == sha256_digest(bundle)
    assert "pinned file" in settings.trust_bundle_source
    gate = config.build_gate(settings)
    assert gate.trust_bundle == bundle
    # With the issuer values also set and agreeing, the file still wins.
    env2 = _env(tmp_path, signer, SigningKey.generate(), PV_TRUST_BUNDLE_FILE=str(path))
    assert config.settings_from_env(env2).trust_bundle == bundle


def test_trust_bundle_file_refuses_malformed_or_mismatched(tmp_path):
    from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC

    signer, witness, other = (
        SigningKey.generate(),
        SigningKey.generate(),
        SigningKey.generate(),
    )
    good = _shared_bundle(signer, witness)
    good["spec"], good["canonicalization"] = TRUST_SPEC, CANONICALIZATION

    def env_with(payload: str, **over: str) -> dict[str, str]:
        path = tmp_path / "bundle.json"
        path.write_text(payload)
        env = _env(
            tmp_path, signer, SigningKey.generate(), PV_TRUST_BUNDLE_FILE=str(path)
        )
        env.pop("PV_ISSUER_ORGANISATION")
        env.pop("PV_ISSUER_KEYS")
        env.update(over)
        return env

    with pytest.raises(config.ConfigError, match="not valid JSON"):
        config.settings_from_env(env_with("{not json"))
    with pytest.raises(config.ConfigError, match="PV_TRUST_BUNDLE_FILE"):
        config.settings_from_env(env_with(json.dumps({"keys": []})))
    no_signer = dict(good, keys=[good["keys"][1]])
    with pytest.raises(config.ConfigError, match="no execution_authorization_signer"):
        config.settings_from_env(env_with(json.dumps(no_signer)))
    with pytest.raises(config.ConfigError, match="differs from PV_ISSUER_ORGANISATION"):
        config.settings_from_env(
            env_with(json.dumps(good), PV_ISSUER_ORGANISATION="other.example")
        )
    with pytest.raises(config.ConfigError, match="does not carry that key"):
        config.settings_from_env(
            env_with(
                json.dumps(good), PV_ISSUER_KEYS=f"ea-signer={encode_public_key(other)}"
            )
        )
    missing = tmp_path / "missing.json"
    env = _env(
        tmp_path, signer, SigningKey.generate(), PV_TRUST_BUNDLE_FILE=str(missing)
    )
    with pytest.raises(config.ConfigError, match="cannot read"):
        config.settings_from_env(env)


def test_mtls_settings_are_all_or_nothing(tmp_path):
    env = _env(tmp_path, SigningKey.generate(), SigningKey.generate())
    cert = tmp_path / "tls.pem"
    cert.write_text("x")
    with pytest.raises(config.ConfigError, match="mTLS needs all of"):
        config.settings_from_env({**env, "PV_RECEIVER_TLS_CERT": str(cert)})
    full = {
        **env,
        "PV_RECEIVER_TLS_CERT": str(cert),
        "PV_RECEIVER_TLS_KEY": str(cert),
        "PV_RECEIVER_CLIENT_CA": str(cert),
        "PV_RECEIVER_REQUIRE_PRESENTER": "1",
    }
    settings = config.settings_from_env(full)
    assert settings.mtls and settings.require_presenter
    assert config.build_gate(settings).require_presenter is True
    with pytest.raises(config.ConfigError, match="not a readable file"):
        config.settings_from_env(
            {**full, "PV_RECEIVER_CLIENT_CA": str(tmp_path / "nope")}
        )


def test_requiring_presenters_without_mtls_refuses_to_start(tmp_path):
    env = {
        **_env(tmp_path, SigningKey.generate(), SigningKey.generate()),
        "PV_RECEIVER_REQUIRE_PRESENTER": "1",
    }
    with pytest.raises(config.ConfigError, match="needs mTLS"):
        config.settings_from_env(env)


def test_serve_launcher_requires_client_certificates(tmp_path):
    """`python -m network.receiver_kit.serve` with the TLS variables serves
    HTTPS that a CA-signed client reaches and others cannot."""
    import http.client
    import os
    import socket
    import ssl
    import time

    from tests.receiver._pki import Pki

    pki = Pki(tmp_path / "pki")
    server, client = pki.leaf("gate", server=True), pki.leaf("agent")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = _env(
        tmp_path,
        SigningKey.generate(),
        SigningKey.generate(),
        PV_RECEIVER_TLS_CERT=str(server.cert),
        PV_RECEIVER_TLS_KEY=str(server.key),
        PV_RECEIVER_CLIENT_CA=str(pki.ca_cert),
        PV_RECEIVER_REQUIRE_PRESENTER="1",
        PV_RECEIVER_HOST="127.0.0.1",
        PV_RECEIVER_PORT=str(port),
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "network.receiver_kit.serve"],
        env={**{k: v for k, v in os.environ.items() if not k.startswith("PV_")}, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def post(with_cert: bool) -> tuple[int, bytes]:
        ctx = ssl.create_default_context(cafile=str(pki.ca_cert))
        if with_cert:
            ctx.load_cert_chain(str(client.cert), str(client.key))
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
        try:
            conn.request("POST", "/v1/payments", body=b"{}")
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()

    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                status, body = post(with_cert=True)
                break
            except (ConnectionRefusedError, ssl.SSLError, OSError) as exc:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(
                        proc.stdout.read().decode() if proc.stdout else ""
                    ) from exc
                time.sleep(0.2)
        assert status == 403 and b"RECEIVER_PERMIT_MISSING" in body
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            post(with_cert=False)
    finally:
        proc.terminate()
        out = proc.communicate(timeout=10)[0].decode()
    assert "client TLS           required" in out
    assert "presenter            required" in out
