"""Generate the run directory: keys, trust bundles, policy, env files.

    uv run python demos/live_checkout/bootstrap.py [--run-dir DIR] [--force]

Everything lands in one directory (``.run/`` by default, ignored by git):

    keys.json, api-key.txt       operator API key for the PrivateVault API
    exec.key                     execution signer (the API mints permits with it)
    witness.key                  sidecar witness/closure key
    trust.json                   the one bundle the API, sidecar and gate pin
    approver/secret.json         the approver's three keys (approve.py only)
    approvers.json               the approver bundle the API pins
    gate/receiver.key, .pub      the gate's receipt key (never leaves the gate)
    policy.yaml, grants.json     compiled from persona.yaml
    services.env                 env for local processes
    services.docker.env          same, with container paths
    approvals/                   the approval inbox

Private keys are written mode 0600. Nothing is printed except public
material.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # run as a script

from nacl.signing import SigningKey  # noqa: E402

from agent_dna.apikeys import generate_key  # noqa: E402
from agent_dna.authority_v01 import (  # noqa: E402
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agents.core.approval import ApproverKit  # noqa: E402
from agents.core.persona import load_persona  # noqa: E402
from demos.live_checkout import config as cfg  # noqa: E402
from network.receiver_kit import keygen  # noqa: E402

PERSONA = cfg.HERE / "persona.yaml"
DOCKER_RUN = "/run/pv"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def execution_bundle(signer: SigningKey, witness: SigningKey) -> dict[str, Any]:
    """Signer and witness keys in one bundle. The API signs with keys[0]."""
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": cfg.ORGANISATION_ID,
        "bundle_version": 1,
        "pinned_at": "2026-01-01T00:00:00Z",
        "keys": [
            {
                "key_id": cfg.EXECUTION_SIGNER_KEY_ID,
                "principal": f"execution-runtime@{cfg.ORGANISATION_ID}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(signer),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": cfg.WITNESS_KEY_ID,
                "principal": f"egress-witness@{cfg.ORGANISATION_ID}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }


def approver_secret(kit: ApproverKit) -> dict[str, str]:
    return {
        "organisation_id": kit.organisation_id,
        "principal": kit.principal,
        "key_id": kit.key_id,
        "root_seed": base64.b64encode(bytes(kit.root_key)).decode(),
        "approver_seed": base64.b64encode(bytes(kit.approver_key)).decode(),
        "receipt_seed": base64.b64encode(bytes(kit.receipt_key)).decode(),
    }


def approver_from_secret(path: Path) -> ApproverKit:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ApproverKit(
        data["organisation_id"],
        principal=data["principal"],
        key_id=data["key_id"],
        root_key=SigningKey(base64.b64decode(data["root_seed"])),
        approver_key=SigningKey(base64.b64decode(data["approver_seed"])),
        receipt_key=SigningKey(base64.b64decode(data["receipt_seed"])),
    )


def _env_lines(root: str, *, upstream: str, tools: list[str]) -> str:
    lines = {
        # PrivateVault API
        "PV_DB_PATH": f"{root}/privatevault/pv.db",
        "PV_API_KEYS_FILE": f"{root}/keys.json",
        "PV_EXECUTION_SIGNER_KEY": f"{root}/exec.key",
        "PV_TRUST_BUNDLE": f"{root}/trust.json",
        "PV_GRANTS_FILE": f"{root}/grants.json",
        "PV_POLICY_FILE": f"{root}/policy.yaml",
        "PV_APPROVER_TRUST_BUNDLE": f"{root}/approvers.json",
        "PV_BASELINE_CAPABILITIES": ",".join(sorted(tools)),
        # Receiver gate (receiver kit config)
        "PV_RECEIVER_ID": cfg.RECEIVER_ID,
        "PV_RECEIVER_DESTINATIONS": cfg.DESTINATION,
        "PV_TRUST_BUNDLE_FILE": f"{root}/trust.json",
        "PV_RECEIPT_KEY_FILE": f"{root}/gate/receiver.key",
        "PV_RECEIPT_KEY_ID": cfg.RECEIPT_KEY_ID,
        "PV_UPSTREAM": upstream,
        "PV_ALLOW_HTTP_UPSTREAM": "1",
        "PV_LEDGER_PATH": f"{root}/gate/receiver.db",
        "PV_UNPROTECTED_OPERATIONS": cfg.UNPROTECTED_OPERATIONS,
        # Local demo on loopback: plain HTTP and no revocation list, both
        # explicit (ADR 0027; a real receiver serves mTLS and pulls the list).
        "PV_RECEIVER_ALLOW_PLAINTEXT": "1",
        "PV_RECEIVER_ALLOW_NO_REVOCATION": "1",
        # ADR 0030/0040: each refund_id is admitted once, so a second decision
        # for the same refund cannot be paid again. Single quotes: the env
        # file parser strips one matching pair.
        "PV_RECEIVER_TRANSACTION_KEYS": "'"
        + json.dumps({cfg.OPERATION: "refund_id"})
        + "'",  # ADR 0041: the server reserves the same key at decide, so a second
        # ALLOW for one refund is blocked while the first can still mint.
        "PV_DECIDE_TRANSACTION_KEYS": "'"
        + json.dumps({cfg.OPERATION: "refund_id"})
        + "'",
        # ADR 0043: per customer per day, counted on the server and claimed
        # atomically, so concurrent refunds cannot all read the same count.
        # The day is India's (UTC+5:30).
        # ADR 0044: tolerate 5 s of clock difference between PrivateVault and
        # the gate at each end of a permit's one-minute window.
        "PV_RECEIVER_CLOCK_SKEW_SECONDS": "5",
        # ADR 0045: PrivateVault checks the refund facts against the payments
        # API's own records (refund-facts/1) before allowing or asking a human.
        "PV_FACT_SOURCES": "'"
        + json.dumps(
            {
                cfg.OPERATION: {
                    "kind": "refund-facts/1",
                    "url": upstream,
                    "timeout_seconds": 2,
                }
            }
        )
        + "'",
        "PV_DECIDE_LIMITS": "'"
        + json.dumps(
            {
                cfg.OPERATION: {
                    "key": "customer_id",
                    "max_count": 3,
                    "max_amount": 60000,
                    "utc_offset_minutes": 330,
                }
            }
        )
        + "'",
    }
    return "".join(f"{k}={v}\n" for k, v in lines.items())


# Raise when services.env or the run layout changes in a way an existing run
# directory would not have: bootstrap then regenerates it.
BOOTSTRAP_VERSION = 4


def bootstrap(
    run_dir: Path, *, force: bool = False, ports: dict[str, int] | None = None
) -> dict[str, Any]:
    ports = ports or cfg.PORTS
    marker = run_dir / "READY"
    if marker.exists() and not force:
        existing = json.loads(marker.read_text(encoding="utf-8"))
        if existing.get("bootstrap_version") == BOOTSTRAP_VERSION:
            return existing
        # Written by an older demo: its services.env lacks settings the
        # current services require (a gate without a transaction key does not
        # start). Regenerate rather than fail later with a startup error.
        print(
            f"run directory {run_dir} was made by an older demo "
            f"(version {existing.get('bootstrap_version', 'unknown')}); "
            "regenerating it",
            file=sys.stderr,
        )
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    (run_dir / "privatevault").mkdir()
    (run_dir / "gate").mkdir()
    (run_dir / "approvals").mkdir()
    (run_dir / "logs").mkdir()

    persona = load_persona(PERSONA)
    compiled = persona.compile(run_dir)

    operator = generate_key(persona.agent_id, "full")
    (run_dir / "keys.json").write_text(
        json.dumps({operator["hash"]: {"name": operator["name"], "scope": "full"}})
    )
    _write_private(run_dir / "api-key.txt", operator["key"].encode())

    signer = SigningKey.generate()
    witness = SigningKey.generate()
    _write_private(run_dir / "exec.key", bytes(signer))
    _write_private(run_dir / "witness.key", bytes(witness))
    bundle = execution_bundle(signer, witness)
    (run_dir / "trust.json").write_text(json.dumps(bundle, indent=2))

    first = persona.approvers[0]
    kit = ApproverKit(
        persona.organisation_id, principal=first["principal"], key_id=first["key_id"]
    )
    _write_private(
        run_dir / "approver" / "secret.json",
        json.dumps(approver_secret(kit), indent=2).encode(),
    )
    (run_dir / "approvers.json").write_text(json.dumps(kit.bundle, indent=2))

    receipt_key = SigningKey.generate()
    keygen.write_key(receipt_key, run_dir / "gate" / "receiver.key")
    (run_dir / "gate" / "receiver.pub").write_text(
        encode_public_key(receipt_key) + "\n"
    )

    # The money tool's capability is the baseline; read tools never reach
    # the API, but declaring them keeps the drift baseline honest.
    tools = ["payments.issue_refund", "payments.order_history"]
    (run_dir / "services.env").write_text(
        _env_lines(
            str(run_dir), upstream=f"http://127.0.0.1:{ports['payments']}", tools=tools
        )
    )
    (run_dir / "services.docker.env").write_text(
        _env_lines(
            DOCKER_RUN, upstream=f"http://payments-api:{ports['payments']}", tools=tools
        )
        .replace(
            f"PV_DB_PATH={DOCKER_RUN}/privatevault/pv.db", "PV_DB_PATH=/data/pv.db"
        )
        .replace(
            f"PV_LEDGER_PATH={DOCKER_RUN}/gate/receiver.db",
            "PV_LEDGER_PATH=/data/receiver.db",
        )
    )

    summary = {
        "run_dir": str(run_dir),
        "agent_id": persona.agent_id,
        "organisation_id": persona.organisation_id,
        "execution_signer_public_key": encode_public_key(signer),
        "witness_public_key": encode_public_key(witness),
        "trust_bundle_digest": sha256_digest(bundle),
        "approver": kit.principal,
        "approver_key_id": kit.key_id,
        "receiver_id": cfg.RECEIVER_ID,
        "receipt_key_id": cfg.RECEIPT_KEY_ID,
        "receipt_public_key": encode_public_key(receipt_key),
        "policy_file": str(compiled.policy_file),
        "grants_file": str(compiled.grants_file),
        "ports": ports,
        "bootstrap_version": BOOTSTRAP_VERSION,
    }
    marker.write_text(json.dumps(summary, indent=2))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--force", action="store_true", help="regenerate everything")
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir) if args.run_dir else cfg.run_dir()
    summary = bootstrap(run_dir, force=args.force)
    print(f"run directory       {summary['run_dir']}")
    print(f"agent               {summary['agent_id']} @ {summary['organisation_id']}")
    print(f"approver            {summary['approver']} ({summary['approver_key_id']})")
    print(f"trust bundle digest {summary['trust_bundle_digest']}")
    print(
        f"gate receipt key    {summary['receipt_key_id']} = {summary['receipt_public_key']}"
    )
    print(f"ports               {summary['ports']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
