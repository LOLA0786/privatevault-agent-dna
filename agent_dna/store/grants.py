"""
Persistent authorization grant store.

Single source of truth for all approved capability evolution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any


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

    def load(self) -> Dict[str, Any]:

        return json.loads(
            self.path.read_text()
        )

    def save(
        self,
        data: Dict[str, Any],
    ) -> None:

        self.path.write_text(
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
            )
        )
