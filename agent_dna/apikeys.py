"""
API key auth for the pilot deployment. Deliberately minimal:

* Keys are NEVER stored — only SHA-256 hashes, loaded from a JSON file
  (PV_API_KEYS_FILE): {"<sha256-hex>": <name-or-entry>, ...}
* generate_key() prints the key ONCE and returns the hash to store.
* No JWT, no tenants — single-enterprise pilot scope.
  (Multi-tenancy machinery is parked on enterprise-suite-wip.)
* If PV_API_KEYS_FILE is unset, auth is DISABLED and the server says
  so loudly at startup — never silently open in a configured pilot.

SCOPE (added for third-party audit access):
* A key file entry can be a plain string (the key's name) -- this
  means scope="full", identical to every key before this feature
  existed. Fully backward compatible; no existing key file needs to
  change.
* A key file entry can instead be an object:
    {"name": "auditor-key-1", "scope": "audit"}
  scope="audit" means the key is valid ONLY for read-only audit
  endpoints (chain verification, audit export) -- never for
  /v1/decide or anything that exercises enforcement authority. This
  is the credential an operator hands to a third-party auditor who
  should be able to verify the audit trail without ever being able
  to act as (or impersonate the authority of) the runtime itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

KEYS_ENV = "PV_API_KEYS_FILE"
VALID_SCOPES = {"full", "audit"}


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key(name: str, scope: str = "full") -> dict[str, str]:
    """scope="full": normal operator key, all endpoints.
    scope="audit": read-only, verify/export endpoints only -- the
    credential to hand a third-party auditor."""
    if scope not in VALID_SCOPES:
        raise ValueError(f"scope must be one of {VALID_SCOPES}, got {scope!r}")
    key = f"pv_{secrets.token_urlsafe(32)}"
    return {"key": key, "hash": _hash(key), "name": name, "scope": scope}


def _normalize_entry(entry: str | dict) -> dict[str, str]:
    """A plain string entry means scope=full (backward compatible with
    every key file that predates the scope concept). A dict entry can
    declare an explicit scope."""
    if isinstance(entry, str):
        return {"name": entry, "scope": "full"}
    name = entry.get("name")
    scope = entry.get("scope", "full")
    if not name:
        raise ValueError(f"key entry missing 'name': {entry}")
    if scope not in VALID_SCOPES:
        raise ValueError(
            f"key entry {name!r} has invalid scope {scope!r}, "
            f"must be one of {VALID_SCOPES}"
        )
    return {"name": name, "scope": scope}


class ApiKeyRegistry:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.getenv(KEYS_ENV)
        self._entries: dict[str, dict[str, str]] = {}
        self.enabled = False
        if self.path:
            data = json.loads(Path(self.path).read_text())
            if not isinstance(data, dict) or not data:
                raise ValueError(f"{self.path}: expected non-empty hash->entry map")
            self._entries = {h: _normalize_entry(v) for h, v in data.items()}
            self.enabled = True

    def verify(self, key: str | None) -> str | None:
        """Returns the key's name if valid, None otherwise. Unchanged
        behavior from before scope existed -- callers that only care
        about 'is this a valid key' are unaffected."""
        entry = self._verify_entry(key)
        return entry["name"] if entry else None

    def _verify_entry(self, key: str | None) -> dict[str, str] | None:
        if not key:
            return None
        return self._entries.get(_hash(key))

    def verify_scope(self, key: str | None, required_scope: str) -> str | None:
        """Returns the key's name if valid AND its scope satisfies the
        requirement, None otherwise. A "full" scope key satisfies any
        requirement (an operator can do everything an auditor can).
        An "audit" scope key satisfies ONLY an "audit" requirement --
        it must never be accepted where "full" (enforcement) access
        is required."""
        entry = self._verify_entry(key)
        if entry is None:
            return None
        if entry["scope"] == "full":
            return entry["name"]
        if entry["scope"] == required_scope:
            return entry["name"]
        return None
