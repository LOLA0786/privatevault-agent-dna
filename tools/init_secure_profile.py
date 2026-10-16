#!/usr/bin/env python3
"""Provision everything ``PV_SECURE_PROFILE=1`` needs, in one directory.

Before this tool the secure profile could only be started by copying test
fixtures (external retests, 2026-10-15/16). It writes:

  keys.json                    hashed API-key registry (no plaintext)
  grants.json                  explicit grants (selftest grants for the
                               deployment verifier, plus --grant entries)
  execution-signer.key   0600  Ed25519 seed that mints execution permits
  dispatch-witness.key   0600  independent seed: dispatch witness + closure
  trust-bundle.json            public keys (execution + receiver trust root)
  secure.env             0600  every PV_* setting, including plaintext API
                               keys and the receipt-signing seed

Nothing secret is printed. The directory is created 0700 and an existing one
is refused unless --replace-existing is passed (no silent key rotation).

    python tools/init_secure_profile.py --out ~/.privatevault/secure \\
        --org acme.example --grant treasury-agent=payments.pay_invoice
    set -a; . ~/.privatevault/secure/secure.env; set +a
    uvicorn api.server:app
    python tools/verify_deployment.py --url http://127.0.0.1:8000 \\
        --api-key "$PV_OPERATOR_KEY" --agent-id operator
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from datetime import UTC, datetime
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
)
from agent_dna.connector.adapters.execution_trust import (  # noqa: E402
    validate_execution_trust_bundle,
)
from agent_dna.signer_python import generate_keypair  # noqa: E402

OPERATOR = "operator"
AUDITOR = "auditor"
SELFTEST_CAPABILITIES = ("pv.selftest.initiate", "pv.selftest.approve")


def _write(path: Path, data: str | bytes, mode: int) -> None:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _prepare(out: Path, replace_existing: bool) -> Path:
    out = out.expanduser().resolve()
    if out.exists():
        if not replace_existing:
            raise FileExistsError(f"refusing to overwrite existing directory: {out}")
        if not out.is_dir():
            raise ValueError(f"{out} exists and is not a directory")
        for child in out.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
            else:
                raise ValueError(f"refusing to replace unexpected subdirectory {child}")
    else:
        out.mkdir(mode=0o700, parents=True)
    os.chmod(out, 0o700)
    return out


def _parse_grant(text: str) -> dict[str, str]:
    agent, sep, capability = text.partition("=")
    if not sep or not agent.strip() or not capability.strip():
        raise argparse.ArgumentTypeError(
            f"--grant must be AGENT=CAPABILITY, got {text!r}"
        )
    return {"agent_id": agent.strip(), "capability": capability.strip()}


def provision(
    out: Path,
    *,
    org: str,
    agents: list[str],
    grants: list[dict[str, str]],
    replace_existing: bool = False,
) -> dict[str, Any]:
    out = _prepare(out, replace_existing)
    names = list(dict.fromkeys([OPERATOR, *agents]))

    api_keys = {name: generate_key(name, "full") for name in names}
    auditor = generate_key(AUDITOR, "audit")
    registry = {
        k["hash"]: {"name": k["name"], "scope": "full"} for k in api_keys.values()
    }
    registry[auditor["hash"]] = {"name": AUDITOR, "scope": "audit"}
    _write(
        out / "keys.json", json.dumps(registry, indent=2, sort_keys=True) + "\n", 0o644
    )

    granted = [
        {"agent_id": OPERATOR, "capability": cap, "granted_by": "init_secure_profile"}
        for cap in SELFTEST_CAPABILITIES
    ] + [{**g, "granted_by": "init_secure_profile"} for g in grants]
    _write(out / "grants.json", json.dumps(granted, indent=2) + "\n", 0o644)

    receipt = generate_keypair()
    ea_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    _write(out / "execution-signer.key", bytes(ea_key), 0o600)
    _write(out / "dispatch-witness.key", bytes(witness_key), 0o600)
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": org,
        "bundle_version": 1,
        "pinned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "keys": [
            {
                "key_id": "execution-signer-01",
                "principal": f"execution-runtime@{org}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(ea_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "dispatch-witness-01",
                "principal": f"egress-witness@{org}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }
    validate_execution_trust_bundle(bundle)
    _write(
        out / "trust-bundle.json",
        json.dumps(bundle, indent=2, sort_keys=True) + "\n",
        0o644,
    )

    env = {
        "PV_SECURE_PROFILE": "1",
        "PV_LINEAGE": "enforce",
        "PV_UNGRANTED_DECISION": "block",
        "PV_DB_PATH": str(out / "privatevault.db"),
        "PV_API_KEYS_FILE": str(out / "keys.json"),
        "PV_GRANTS_FILE": str(out / "grants.json"),
        "PV_RECEIPT_SIGNING_KEY": receipt["signing_key"],
        "PV_TRUSTED_PUBLIC_KEYS": receipt["public_key"],
        "PV_EXECUTION_SIGNER_KEY": str(out / "execution-signer.key"),
        "PV_TRUST_BUNDLE": str(out / "trust-bundle.json"),
        "PV_EXECUTION_TRUST_BUNDLE_FILE": str(out / "trust-bundle.json"),
        "PV_DISPATCH_WITNESS_KEY": str(out / "dispatch-witness.key"),
        "PV_OPERATOR_KEY": api_keys[OPERATOR]["key"],
        "PV_AUDITOR_KEY": auditor["key"],
    }
    for name in names:
        if name != OPERATOR:
            var = "PV_KEY_" + "".join(c if c.isalnum() else "_" for c in name).upper()
            env[var] = api_keys[name]["key"]
    lines = ["# PrivateVault secure profile. Secrets: keep this file 0600."]
    lines += [f"{k}={shlex.quote(v)}" for k, v in env.items()]
    _write(out / "secure.env", "\n".join(lines) + "\n", 0o600)

    return {
        "out": str(out),
        "organisation_id": org,
        "agents": names,
        "receipt_public_key": receipt["public_key"],
        "env_file": str(out / "secure.env"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, required=True, help="new directory")
    parser.add_argument("--org", default="privatevault.local", help="organisation id")
    parser.add_argument(
        "--agent", action="append", default=[], help="extra agent API key (repeat)"
    )
    parser.add_argument(
        "--grant",
        action="append",
        default=[],
        type=_parse_grant,
        help="AGENT=CAPABILITY grant (repeat); the agent gets an API key too",
    )
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args(argv)
    agents = [*args.agent, *(g["agent_id"] for g in args.grant)]
    try:
        info = provision(
            args.out,
            org=args.org,
            agents=agents,
            grants=args.grant,
            replace_existing=args.replace_existing,
        )
    except (FileExistsError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"wrote secure profile to {info['out']}")
    print(
        f"agents with API keys: {', '.join(info['agents'])} (+ {AUDITOR}, audit scope)"
    )
    print(f"receipt public key: {info['receipt_public_key']}")
    print("secrets are in secure.env (mode 0600); nothing secret was printed")
    print(f"load it with:  set -a; . {info['env_file']}; set +a")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
