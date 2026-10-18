#!/usr/bin/env python3
"""Check a KMS signing key against a live KMS before configuring it.

    python tools/kms_smoke.py awskms:arn:aws:kms:REGION:ACCOUNT:key/KEY_ID
    python tools/kms_smoke.py gcpkms:projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1

Uses the normal credential chain (AWS_PROFILE / instance role; gcloud
application-default credentials). It reads the public key, signs a probe
and a 4 KB document, verifies both locally with the public key, and prints
the public key in the two forms PrivateVault configuration uses:

* base64, for a trust bundle ``keys[].public_key`` (execution signer,
  dispatch witness, receiver receipts);
* hex, for ``PV_TRUSTED_PUBLIC_KEYS`` (decision receipt signer).

Nothing is created, changed or stored. Exit 0 only if every check passed.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nacl.signing import VerifyKey  # noqa: E402

from agent_dna.key_custody import SignerError, is_kms_ref, kms_signer  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not is_kms_ref(args[0]):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        signer = kms_signer(args[0])
        verify = VerifyKey(signer.public_key)
        timings = []
        for message in (b"privatevault kms smoke probe", b"x" * 4000):
            started = time.perf_counter()
            signature = signer.sign(message)
            timings.append((time.perf_counter() - started) * 1000)
            verify.verify(message, signature)
    except SignerError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # anything else is a failed check too
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "key": signer.description,
                "public_key_base64": base64.b64encode(signer.public_key).decode(),
                "public_key_hex": signer.public_key.hex(),
                "sign_ms": [round(t, 1) for t in timings],
                "checks": [
                    "Ed25519 key (spec/algorithm checked)",
                    "probe and 4000-byte document signed and verified locally",
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
