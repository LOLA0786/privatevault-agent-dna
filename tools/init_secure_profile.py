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
  operations.json              the operations each capability covers (empty)
  presenters/client-ca.pem     CA for agent TLS client certificates; give it
                               to receivers as PV_RECEIVER_CLIENT_CA
  presenters/client-ca.key 0600  its key: issue more agents with it, then
                               store it offline
  presenters/<agent>.pem/.key  one TLS client certificate per API-key holder
                               (key 0600), for that agent's sidecar
  presenter-bundle.json        pins each agent's client key (ADR 0022/0028)
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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402
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
from agent_dna.operation_registry import (  # noqa: E402
    OPERATIONS_SPEC,
    parse_operation_registry,
)
from agent_dna.presenter_identity import (  # noqa: E402
    PRESENTER_BUNDLE_SPEC,
    presenter_identity_digest,
    validate_presenter_bundle,
)
from agent_dna.signer_python import generate_keypair  # noqa: E402

OPERATOR = "operator"
AUDITOR = "auditor"
SELFTEST_CAPABILITIES = ("pv.selftest.initiate", "pv.selftest.approve")
CA_DAYS = 3 * 365
CLIENT_DAYS = 365


def _name(common_name: str, org: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _presenters(out: Path, org: str, agents: list[str]) -> dict[str, list[str]]:
    """A client CA and one TLS client certificate per agent (ADR 0028).

    Each agent's sidecar presents its certificate to receivers; the presenter
    bundle pins the certificate's key, so a permit minted for the agent can
    only be presented by it (ADR 0022). Returns agent -> pinned digests.
    """
    now = datetime.now(UTC) - timedelta(minutes=5)
    directory = out / "presenters"
    directory.mkdir(mode=0o700)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name(f"PrivateVault agent client CA ({org})", org)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write(directory / "client-ca.key", _key_pem(ca_key), 0o600)
    _write(
        directory / "client-ca.pem", ca.public_bytes(serialization.Encoding.PEM), 0o644
    )
    pinned: dict[str, list[str]] = {}
    for agent in agents:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(agent, org))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=CLIENT_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        stem = "".join(c if c.isalnum() or c in "-._" else "_" for c in agent)
        _write(directory / f"{stem}.key", _key_pem(key), 0o600)
        _write(
            directory / f"{stem}.pem",
            cert.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        pinned[agent] = [
            presenter_identity_digest(cert.public_bytes(serialization.Encoding.DER))
        ]
    return pinned


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
            elif child.name == "presenters" and all(
                c.is_file() or c.is_symlink() for c in child.iterdir()
            ):
                for c in child.iterdir():
                    c.unlink()  # a symlink is removed, never followed
                child.rmdir()
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
    operations: list[dict[str, Any]] | None = None,
    baseline_from_grants: bool = False,
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

    # ADR 0025: the secure profile mints only operations declared here. The
    # file starts empty, so nothing mints until the operator declares the
    # exact method, destination and route each capability may use.
    registry = {"spec": OPERATIONS_SPEC, "operations": list(operations or [])}
    parse_operation_registry(registry)  # refuse a bad declaration now
    _write(out / "operations.json", json.dumps(registry, indent=2) + "\n", 0o644)

    presenters = {
        "spec": PRESENTER_BUNDLE_SPEC,
        "organisation_id": org,
        "presenters": _presenters(out, org, names),
    }
    validate_presenter_bundle(presenters)
    _write(
        out / "presenter-bundle.json",
        json.dumps(presenters, indent=2, sort_keys=True) + "\n",
        0o644,
    )

    env = {
        "PV_SECURE_PROFILE": "1",
        "PV_LINEAGE": "enforce",
        "PV_UNGRANTED_DECISION": "block",
        "PV_DB_PATH": str(out / "privatevault.db"),
        "PV_API_KEYS_FILE": str(out / "keys.json"),
        "PV_GRANTS_FILE": str(out / "grants.json"),
        "PV_OPERATIONS_FILE": str(out / "operations.json"),
        "PV_RECEIPT_SIGNING_KEY": receipt["signing_key"],
        "PV_TRUSTED_PUBLIC_KEYS": receipt["public_key"],
        "PV_EXECUTION_SIGNER_KEY": str(out / "execution-signer.key"),
        "PV_TRUST_BUNDLE": str(out / "trust-bundle.json"),
        "PV_EXECUTION_TRUST_BUNDLE_FILE": str(out / "trust-bundle.json"),
        "PV_DISPATCH_WITNESS_KEY": str(out / "dispatch-witness.key"),
        "PV_PRESENTER_BUNDLE": str(out / "presenter-bundle.json"),
        "PV_OPERATOR_KEY": api_keys[OPERATOR]["key"],
        "PV_AUDITOR_KEY": auditor["key"],
    }
    granted_caps = sorted({g["capability"] for g in grants})
    if baseline_from_grants and granted_caps:
        # Opt-in: treat the explicitly granted capabilities as normal for the
        # synthetic drift scorer, so a granted first action (e.g. `ls` under
        # shell.exec) is not held for drift review. Policy, shell guard and
        # grants still apply; only the novelty signal is relaxed.
        env["PV_BASELINE_CAPABILITIES"] = ",".join(granted_caps)
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
        "client_ca": str(out / "presenters" / "client-ca.pem"),
        "granted_capabilities": granted_caps,
        "baseline_capabilities": granted_caps if baseline_from_grants else [],
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
    parser.add_argument(
        "--baseline-from-grants",
        action="store_true",
        help="write PV_BASELINE_CAPABILITIES from the --grant capabilities, so a "
        "granted capability is not held for drift review on first use",
    )
    args = parser.parse_args(argv)
    agents = [*args.agent, *(g["agent_id"] for g in args.grant)]
    try:
        info = provision(
            args.out,
            org=args.org,
            agents=agents,
            grants=args.grant,
            replace_existing=args.replace_existing,
            baseline_from_grants=args.baseline_from_grants,
        )
    except (FileExistsError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"wrote secure profile to {info['out']}")
    print(
        f"agents with API keys: {', '.join(info['agents'])} (+ {AUDITOR}, audit scope)"
    )
    print(f"receipt public key: {info['receipt_public_key']}")
    print(
        f"agent client certificates in {info['out']}/presenters; give receivers "
        f"{info['client_ca']} as PV_RECEIVER_CLIENT_CA"
    )
    print("secrets are in secure.env (mode 0600); nothing secret was printed")
    print(f"load it with:  set -a; . {info['env_file']}; set +a")
    if info["baseline_capabilities"]:
        print(
            "drift baseline (PV_BASELINE_CAPABILITIES): "
            + ",".join(info["baseline_capabilities"])
        )
    elif info["granted_capabilities"]:
        print(
            "note: granted capabilities ("
            + ",".join(info["granted_capabilities"])
            + ") are not in the drift baseline, so their first uses may be held "
            "for approval (202, triggered_by=drift). Re-run with "
            "--baseline-from-grants or set PV_BASELINE_CAPABILITIES to accept them."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
