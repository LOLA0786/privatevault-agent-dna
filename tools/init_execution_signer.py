#!/usr/bin/env python3
"""Bootstrap the execution-authorization signing identity.

The private key written here mints execution authority. It must never leave
the control plane and must never be readable by an agent process.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)

ORG = os.environ.get("PV_ORGANISATION_ID", "store.example")
OUT = Path(os.environ.get("PV_SIGNER_DIR", Path.home() / ".privatevault"))
OUT.mkdir(parents=True, exist_ok=True)

key_path = OUT / "execution-signer.key"
bundle_path = OUT / "trust-bundle.json"

if key_path.exists():
    sys.exit(f"refusing to overwrite existing key: {key_path}")

signing_key = SigningKey.generate()
key_path.write_bytes(bytes(signing_key))
os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

bundle = {
    "spec": TRUST_SPEC,
    "canonicalization": CANONICALIZATION,
    "organisation_id": ORG,
    "bundle_version": 1,
    "pinned_at": "2026-07-31T00:00:00Z",
    "keys": [
        {
            "key_id": "execution-signer-01",
            "principal": f"execution-runtime@{ORG}",
            "algorithm": "ed25519",
            "public_key": encode_public_key(signing_key),
            "usages": ["execution_authorization_signer"],
        }
    ],
}
bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True))

print(f"private key   : {key_path}  (mode 0600)")
print(f"trust bundle  : {bundle_path}")
print()
print("export PV_EXECUTION_SIGNER_KEY=" + str(key_path))
print("export PV_TRUST_BUNDLE=" + str(bundle_path))
