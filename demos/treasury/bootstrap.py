"""Generate the treasury run directory: two agent identities, keys, the
shared trust bundle, the approver, the gate's receipt key, the merged
policy and grants, env files.

    uv run python demos/treasury/bootstrap.py [--run-dir DIR] [--force]

    keys.json                    hashed operator keys for both agents
    agents/<agent_id>.key        each agent's own API key (0600)
    exec.key, witness.key        execution signer and sidecar witness
    trust.json                   the one bundle the API, sidecars and gate pin
    approver/secret.json         the treasury approver's keys (approve.py only)
    approvers.json               the approver bundle the API pins
    gate/receiver.key, .pub      the gate's receipt key
    policy.yaml, grants.json     both personas merged
    services.env                 env for the three services (replay retention on)
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

import yaml  # noqa: E402
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
from demos.treasury import config as cfg  # noqa: E402
from network.receiver_kit import keygen  # noqa: E402

PERSONAS = (
    cfg.HERE / "personas" / "ap_agent.yaml",
    cfg.HERE / "personas" / "treasury_agent.yaml",
)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def execution_bundle(signer: SigningKey, witness: SigningKey) -> dict[str, Any]:
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


def merged_policy_and_grants(run_dir: Path) -> tuple[Path, Path, list[str]]:
    """Both personas into the one policy file and one grants file the API
    loads. Rules keep their persona order: blocks before approvals."""
    rules: list[dict[str, Any]] = []
    grants: list[dict[str, Any]] = []
    capabilities: set[str] = set()
    for path in PERSONAS:
        persona = load_persona(path)
        rules.extend(dict(rule) for rule in persona.policy)
        for grant in persona.grants:
            entry: dict[str, Any] = {
                "agent_id": persona.agent_id,
                "capability": grant["capability"],
                "granted_by": f"persona:{persona.name}",
            }
            if "budget" in grant:
                entry["budget"] = grant["budget"]
            grants.append(entry)
            capabilities.add(grant["capability"])
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids across personas")
    policy_file = run_dir / "policy.yaml"
    policy_file.write_text(
        yaml.safe_dump({"version": "1.0", "policies": rules}, sort_keys=False)
    )
    grants_file = run_dir / "grants.json"
    grants_file.write_text(json.dumps(grants, indent=2))
    return policy_file, grants_file, sorted(capabilities)


def _env_lines(root: str, *, upstream: str, capabilities: list[str]) -> str:
    lines = {
        "PV_DB_PATH": f"{root}/privatevault/pv.db",
        "PV_API_KEYS_FILE": f"{root}/keys.json",
        "PV_EXECUTION_SIGNER_KEY": f"{root}/exec.key",
        "PV_TRUST_BUNDLE": f"{root}/trust.json",
        "PV_GRANTS_FILE": f"{root}/grants.json",
        "PV_POLICY_FILE": f"{root}/policy.yaml",
        "PV_APPROVER_TRUST_BUNDLE": f"{root}/approvers.json",
        "PV_BASELINE_CAPABILITIES": ",".join(capabilities),
        # Opt-in retention of rule inputs so PolicyReplay can re-evaluate
        # this run's sealed decisions (docs/POLICY-REPLAY.md boundary).
        "PV_REPLAY_FIELDS": ",".join(cfg.REPLAY_FIELDS),
        "PV_REPLAY_DB": f"{root}/privatevault/replay.db",
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
    }
    return "".join(f"{k}={v}\n" for k, v in lines.items())


def bootstrap(
    run_dir: Path, *, force: bool = False, ports: dict[str, int] | None = None
) -> dict[str, Any]:
    ports = ports or cfg.PORTS
    marker = run_dir / "READY"
    if marker.exists() and not force:
        return json.loads(marker.read_text(encoding="utf-8"))
    if run_dir.exists():
        shutil.rmtree(run_dir)
    for sub in ("privatevault", "gate", "approvals", "logs", "agents", "export"):
        (run_dir / sub).mkdir(parents=True)

    policy_file, grants_file, capabilities = merged_policy_and_grants(run_dir)

    keys: dict[str, Any] = {}
    for agent_id in cfg.AGENTS:
        operator = generate_key(agent_id, "full")
        keys[operator["hash"]] = {"name": operator["name"], "scope": "full"}
        _write_private(run_dir / "agents" / f"{agent_id}.key", operator["key"].encode())
    auditor = generate_key("auditor", "audit")
    keys[auditor["hash"]] = {"name": "auditor", "scope": "audit"}
    _write_private(run_dir / "agents" / "auditor.key", auditor["key"].encode())
    (run_dir / "keys.json").write_text(json.dumps(keys))

    signer, witness = SigningKey.generate(), SigningKey.generate()
    _write_private(run_dir / "exec.key", bytes(signer))
    _write_private(run_dir / "witness.key", bytes(witness))
    bundle = execution_bundle(signer, witness)
    (run_dir / "trust.json").write_text(json.dumps(bundle, indent=2))

    kit = ApproverKit(
        cfg.ORGANISATION_ID,
        principal=cfg.APPROVER_PRINCIPAL,
        key_id=cfg.APPROVER_KEY_ID,
    )
    _write_private(
        run_dir / "approver" / "secret.json",
        json.dumps(approver_secret(kit), indent=2).encode(),
    )
    (run_dir / "approvers.json").write_text(json.dumps(kit.bundle, indent=2))
    # A second, unpinned approver: its signatures must be refused.
    rogue = ApproverKit(
        cfg.ORGANISATION_ID,
        principal="ap-clerk@corp.example",
        key_id="approver-ap-clerk",
    )
    _write_private(
        run_dir / "approver" / "unpinned.json",
        json.dumps(approver_secret(rogue), indent=2).encode(),
    )

    receipt_key = SigningKey.generate()
    keygen.write_key(receipt_key, run_dir / "gate" / "receiver.key")
    (run_dir / "gate" / "receiver.pub").write_text(
        encode_public_key(receipt_key) + "\n"
    )

    (run_dir / "services.env").write_text(
        _env_lines(
            str(run_dir),
            upstream=f"http://127.0.0.1:{ports['bank']}",
            capabilities=capabilities,
        )
    )
    summary = {
        "run_dir": str(run_dir),
        "agents": list(cfg.AGENTS),
        "organisation_id": cfg.ORGANISATION_ID,
        "trust_bundle_digest": sha256_digest(bundle),
        "approver": kit.principal,
        "receiver_id": cfg.RECEIVER_ID,
        "receipt_key_id": cfg.RECEIPT_KEY_ID,
        "receipt_public_key": encode_public_key(receipt_key),
        "policy_file": str(policy_file),
        "grants_file": str(grants_file),
        "replay_fields": list(cfg.REPLAY_FIELDS),
        "ports": ports,
    }
    marker.write_text(json.dumps(summary, indent=2))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    summary = bootstrap(
        Path(args.run_dir) if args.run_dir else cfg.run_dir(), force=args.force
    )
    for key in (
        "run_dir",
        "agents",
        "approver",
        "trust_bundle_digest",
        "receipt_key_id",
        "receipt_public_key",
        "replay_fields",
        "ports",
    ):
        print(f"{key:<20} {summary[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
