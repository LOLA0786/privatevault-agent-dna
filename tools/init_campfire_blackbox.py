#!/usr/bin/env python3
"""Bootstrap a dedicated Campfire black-box runtime directory.

Writes hashed API keys, 0600 secrets, independent signing material,
grants, and a deterministic evaluation policy. Refuses to overwrite
unless --replace-existing is passed. Never prints private material.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.signing import SigningKey  # noqa: E402

from agent_dna.apikeys import generate_key  # noqa: E402
from agent_dna.authority_v01 import (  # noqa: E402
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    validate_trust_bundle,
)
from agent_dna.connector.adapters.execution_trust import (  # noqa: E402
    validate_execution_trust_bundle,
)
from agent_dna.policy.loader import load_policy_file  # noqa: E402
from agent_dna.signer_python import generate_keypair  # noqa: E402

AGENT_ID = "campfire-agent"
AUDITOR_ID = "campfire-auditor"
CAPABILITY = "campfire.files.write_sandbox"
ORG = "campfire.eval"
PINNED_AT = "2026-08-19T00:00:00Z"
ALLOW_PATH = "/sandbox/notes.txt"
BLOCK_PATH = "/protected/secrets.txt"

POLICY_YAML = """version: "1.0"
policies:
  - id: campfire-protected-path
    capability: campfire.files.write_sandbox
    outcome: block
    reason: "protected paths are not writable in the evaluation sandbox"
    condition:
      field: arguments.path
      operator: "=="
      value: /protected/secrets.txt
  - id: campfire-review-required
    capability: campfire.files.write_sandbox
    outcome: require_approval
    reason: "review=true requires a human before the sandbox write"
    condition:
      field: arguments.review
      operator: "=="
      value: true
"""

REQUIRED_FILES = (
    "keys.json",
    "keys.secrets.txt",
    "execution-signer.key",
    "dispatch-witness.key",
    "trust-bundle.json",
    "execution-trust-bundle.json",
    "public-trust-bundle.json",
    "grants.json",
    "policy.yaml",
)


def _chmod(path: Path, mode: int) -> None:
    os.chmod(path, mode)


def _write_bytes(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    _chmod(path, mode)


def _write_text(path: Path, text: str, mode: int) -> None:
    _write_bytes(path, text.encode("utf-8"), mode)


def validate_runtime_dir(out: Path) -> None:
    if not out.is_dir():
        raise FileNotFoundError(f"runtime directory missing: {out}")
    missing = [name for name in REQUIRED_FILES if not (out / name).is_file()]
    if missing:
        raise FileNotFoundError(
            "incomplete Campfire runtime directory: " + ", ".join(missing)
        )
    for name in ("keys.secrets.txt", "execution-signer.key", "dispatch-witness.key"):
        mode = stat.S_IMODE((out / name).stat().st_mode)
        if mode != 0o600:
            raise ValueError(f"{name} must be mode 0600, got {oct(mode)}")
    secrets = (out / "keys.secrets.txt").read_text(encoding="utf-8")
    for required in (
        "CAMPFIRE_API_KEY=",
        "CAMPFIRE_AUDIT_KEY=",
        "PV_RECEIPT_SIGNING_KEY=",
        "PV_TRUSTED_PUBLIC_KEY=",
    ):
        if required not in secrets:
            raise ValueError(f"secrets file missing {required[:-1]}")
    registry = json.loads((out / "keys.json").read_text(encoding="utf-8"))
    if "pv_" in json.dumps(registry):
        raise ValueError("API-key registry must store hashes only")
    load_policy_file(out / "policy.yaml")
    grants = json.loads((out / "grants.json").read_text(encoding="utf-8"))
    if not isinstance(grants, list) or not grants:
        raise ValueError("grants.json must be a non-empty list")
    if grants[0].get("capability") != CAPABILITY:
        raise ValueError("grants must be limited to the sandbox write capability")
    bundle = json.loads(
        (out / "execution-trust-bundle.json").read_text(encoding="utf-8")
    )
    validate_trust_bundle(bundle)
    validate_execution_trust_bundle(bundle)


def bootstrap(out: Path, *, replace_existing: bool = False) -> dict[str, Any]:
    out = out.resolve()
    if out.exists():
        if not replace_existing:
            raise FileExistsError(
                f"refusing to overwrite existing runtime directory: {out}"
            )
        if not out.is_dir():
            raise ValueError(f"{out} exists and is not a directory")
        for child in out.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
            else:
                raise ValueError(f"refusing to replace unexpected subdirectory {child}")
    else:
        out.mkdir(mode=0o700, parents=True)
    _chmod(out, 0o700)

    operator = generate_key(AGENT_ID, "full")
    auditor = generate_key(AUDITOR_ID, "audit")
    registry = {
        operator["hash"]: {"name": operator["name"], "scope": "full"},
        auditor["hash"]: {"name": auditor["name"], "scope": "audit"},
    }
    _write_text(
        out / "keys.json", json.dumps(registry, indent=2, sort_keys=True) + "\n", 0o644
    )

    receipt = generate_keypair()
    ea_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    _write_bytes(out / "execution-signer.key", bytes(ea_key), 0o600)
    _write_bytes(out / "dispatch-witness.key", bytes(witness_key), 0o600)

    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": PINNED_AT,
        "keys": [
            {
                "key_id": "campfire-ea-signer",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(ea_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "campfire-witness-01",
                "principal": f"egress-witness@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }
    validate_execution_trust_bundle(bundle)
    public_json = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    _write_text(out / "trust-bundle.json", public_json, 0o644)
    _write_text(out / "execution-trust-bundle.json", public_json, 0o644)
    _write_text(out / "public-trust-bundle.json", public_json, 0o644)

    grants = [
        {
            "agent_id": AGENT_ID,
            "capability": CAPABILITY,
            "granted_by": "campfire-eval",
        }
    ]
    _write_text(out / "grants.json", json.dumps(grants, indent=2) + "\n", 0o644)
    _write_text(out / "policy.yaml", POLICY_YAML, 0o644)

    secrets = "\n".join(
        [
            f"CAMPFIRE_API_KEY={operator['key']}",
            f"CAMPFIRE_AUDIT_KEY={auditor['key']}",
            f"PV_RECEIPT_SIGNING_KEY={receipt['signing_key']}",
            f"PV_TRUSTED_PUBLIC_KEY={receipt['public_key']}",
            "",
        ]
    )
    _write_text(out / "keys.secrets.txt", secrets, 0o600)
    validate_runtime_dir(out)
    print(f"wrote Campfire runtime directory {out}")
    print("plaintext keys and signing seeds are in keys.secrets.txt (mode 0600)")
    print("private signing files are mode 0600 and are not printed")
    print(f"set PV_BASELINE_CAPABILITIES={CAPABILITY}")
    return {
        "agent_id": AGENT_ID,
        "auditor_id": AUDITOR_ID,
        "capability": CAPABILITY,
        "organisation_id": ORG,
        "output": str(out),
        "receipt_public_key": receipt["public_key"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "deploy" / "partners" / "campfire-blackbox" / "runtime",
        help="Runtime directory (gitignored). Refused if it already exists.",
    )
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="Explicitly replace an existing runtime directory. Not silent rotation.",
    )
    args = parser.parse_args()
    bootstrap(args.out, replace_existing=args.replace_existing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
