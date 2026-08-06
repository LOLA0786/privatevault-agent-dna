"""
Persistent storage for Agent DNA profiles.

Stores versioned behavioral identities as JSON snapshots.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .fingerprint import AgentFingerprint


class ProfileStore:
    def __init__(self, root: str = "profiles") -> None:
        self.root = Path(root)

    def save(
        self,
        fingerprint: AgentFingerprint,
        version: str,
    ) -> Path:

        folder = self.root / fingerprint.agent_id
        folder.mkdir(parents=True, exist_ok=True)

        outfile = folder / f"{version}.json"

        outfile.write_text(
            json.dumps(
                asdict(fingerprint),
                indent=2,
            )
        )

        return outfile

    def load(
        self,
        agent_id: str,
        version: str,
    ) -> AgentFingerprint:

        infile = self.root / agent_id / f"{version}.json"

        data = json.loads(infile.read_text())

        return AgentFingerprint(**data)

    def versions(
        self,
        agent_id: str,
    ) -> list[str]:

        folder = self.root / agent_id

        if not folder.exists():
            return []

        return sorted(p.stem for p in folder.glob("*.json"))
