"""
Persistent authorization grant store.

Persistence backend for the change-management workflow ONLY. DEPRECATED as an authorization source (audit set 4): the canonical grant model is agent_dna.grants.GrantRegistry. Two modules calling themselves 'single source of truth' was itself the finding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class GrantStore:
    def __init__(
        self,
        path: str = "profiles/grants.json",
    ):
        self.path = Path(path)

        if not self.path.exists():
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self.path.write_text("{}")

    def load(self) -> dict[str, Any]:

        return json.loads(self.path.read_text())

    def save(
        self,
        data: dict[str, Any],
    ) -> None:

        self.path.write_text(
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
            )
        )
