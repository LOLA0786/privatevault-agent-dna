#!/usr/bin/env python3
"""Generate operator + auditor API keys for the platform compose profile."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from agent_dna.apikeys import generate_key  # noqa: E402

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("deploy/platform/keys.json"),
        help="Hashed key registry path mounted into the API container",
    )
    parser.add_argument(
        "--secrets-out",
        type=Path,
        default=Path("deploy/platform/keys.secrets.txt"),
        help="Plaintext keys for the operator (do not commit)",
    )
    args = parser.parse_args()

    op = generate_key("payments-agent", "full")
    au = generate_key("auditor", "audit")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                op["hash"]: {"name": op["name"], "scope": "full"},
                au["hash"]: {"name": au["name"], "scope": "audit"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    args.secrets_out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.secrets_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"OPERATOR_KEY={op['key']}\nAUDITOR_KEY={au['key']}\n")
    os.chmod(args.secrets_out, 0o600)  # also tighten a pre-existing file
    # Keys are never printed: stdout ends up in CI logs and scrollback.
    print(f"wrote registry {args.out}")
    print(f"wrote secrets  {args.secrets_out} (mode 0600, gitignored; do not commit)")
    print(f"read them with: cat {args.secrets_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
