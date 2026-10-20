#!/usr/bin/env python3
"""Convert the legacy per-agent grants format to a PV_GRANTS_FILE list.

Legacy (profiles/grants.json, read by the skill adapter)::

    {"agent": {"capability": {"approved_by", "capability", "environment",
                              "expires_at", "ticket", "version"}}}

PV_GRANTS_FILE (agent_dna.composition._load_grants)::

    [{"agent_id", "capability", "granted_by", "expires_at", ...}]

The loader does not accept the legacy shape on purpose: the legacy entry is
scoped to an ``environment`` and a ``version`` that PV_GRANTS_FILE cannot
express, so loading it silently would widen each grant. This tool makes the
narrowing explicit: only entries for ``--environment`` are written, and an
entry pinned to a specific version is refused unless ``--allow-version-pins``
is given (the pin is then dropped and noted in the output).

    python tools/migrate_grants.py profiles/grants.json \
        --environment prod --out grants.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def migrate(  # noqa: C901 - one branch per legacy shape
    legacy: object, environment: str, allow_version_pins: bool = False
) -> tuple[list[dict], list[str]]:
    if not isinstance(legacy, dict):
        raise ValueError(
            "legacy grants must be a JSON object {agent: {capability: {...}}}"
        )
    out: list[dict] = []
    notes: list[str] = []
    for agent, caps in legacy.items():
        if not isinstance(caps, dict):
            raise ValueError(f"{agent!r}: expected an object of capabilities")
        for cap_key, entry in caps.items():
            if not isinstance(entry, dict):
                raise ValueError(f"{agent!r}/{cap_key!r}: expected an object")
            cap = entry.get("capability", cap_key)
            if cap != cap_key:
                raise ValueError(
                    f"{agent!r}: key {cap_key!r} disagrees with capability {cap!r}"
                )
            env = entry.get("environment")
            if env not in (None, "*", environment):
                notes.append(
                    f"skipped {agent}/{cap}: environment {env!r} != {environment!r}"
                )
                continue
            version = entry.get("version", "*")
            if version not in (None, "*"):
                if not allow_version_pins:
                    raise ValueError(
                        f"{agent!r}/{cap!r} is pinned to version {version!r}, which "
                        "PV_GRANTS_FILE cannot express; pass --allow-version-pins to drop it"
                    )
                notes.append(f"dropped version pin {version!r} on {agent}/{cap}")
            g = {
                "agent_id": agent,
                "capability": cap,
                "granted_by": entry.get("approved_by") or "legacy-migration",
                "expires_at": entry.get("expires_at"),
            }
            if entry.get("ticket"):
                g["ticket"] = entry["ticket"]
            out.append(g)
    return out, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("legacy", type=Path)
    ap.add_argument(
        "--environment", required=True, help="keep only grants for this environment"
    )
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--allow-version-pins", action="store_true")
    a = ap.parse_args(argv)
    try:
        grants, notes = migrate(
            json.loads(a.legacy.read_text()), a.environment, a.allow_version_pins
        )
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    a.out.write_text(json.dumps(grants, indent=2) + "\n")
    for n in notes:
        print(n, file=sys.stderr)
    print(f"wrote {len(grants)} grant(s) to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
