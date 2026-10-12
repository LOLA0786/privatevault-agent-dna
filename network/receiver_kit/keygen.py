"""Generate an Ed25519 key pair on this machine. Nothing leaves it.

    python -m network.receiver_kit.keygen receiver   # the partner's receipt key
    python -m network.receiver_kit.keygen issuer     # a demo issuer key for send_test

Writes ``<out>/<name>.key`` (base64 seed, mode 0600, never overwritten) and
``<out>/<name>.pub`` (base64 public key). Prints the public key only.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

from agent_dna.authority_v01 import encode_public_key

NAMES = {"receiver": "receiver", "issuer": "issuer"}


def write_key(key: SigningKey, path: Path) -> None:
    """Create ``path`` with mode 0600; refuse if it already exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(bytes(key)).decode("ascii") + "\n")


def generate(kind: str, out: Path) -> tuple[Path, Path, str]:
    name = NAMES[kind]
    key_path = out / f"{name}.key"
    pub_path = out / f"{name}.pub"
    if key_path.exists() or pub_path.exists():
        raise FileExistsError(
            f"{key_path} or {pub_path} already exists; not overwriting"
        )
    key = SigningKey.generate()
    write_key(key, key_path)
    public = encode_public_key(key)
    pub_path.write_text(public + "\n", encoding="ascii")
    return key_path, pub_path, public


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=sorted(NAMES))
    parser.add_argument("--out", default="keys", help="directory (default: ./keys)")
    args = parser.parse_args(argv)
    try:
        key_path, pub_path, public = generate(args.kind, Path(args.out))
    except FileExistsError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"private key written to {key_path} (mode 0600, keep it here)")
    print(f"public key written to  {pub_path}")
    print(f"{args.kind} public key: {public}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
