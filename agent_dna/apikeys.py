"""
API key auth for the pilot deployment. Deliberately minimal:

* Keys are NEVER stored — only SHA-256 hashes, loaded from a JSON file
  (PV_API_KEYS_FILE): {"<sha256-hex>": "<key name>", ...}
* generate_key() prints the key ONCE and returns the hash to store.
* No JWT, no tenants, no roles — single-enterprise pilot scope.
  (Multi-tenancy machinery is parked on enterprise-suite-wip.)
* If PV_API_KEYS_FILE is unset, auth is DISABLED and the server says
  so loudly at startup — never silently open in a configured pilot.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Dict, Optional

KEYS_ENV = "PV_API_KEYS_FILE"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key(name: str) -> Dict[str, str]:
    key = f"pv_{secrets.token_urlsafe(32)}"
    return {"key": key, "hash": _hash(key), "name": name}


class ApiKeyRegistry:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.getenv(KEYS_ENV)
        self._hashes: Dict[str, str] = {}
        self.enabled = False
        if self.path:
            data = json.loads(Path(self.path).read_text())
            if not isinstance(data, dict) or not data:
                raise ValueError(f"{self.path}: expected non-empty hash->name map")
            self._hashes = data
            self.enabled = True

    def verify(self, key: Optional[str]) -> Optional[str]:
        """Returns the key's name if valid, None otherwise."""
        if not key:
            return None
        return self._hashes.get(_hash(key))
