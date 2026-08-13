"""Deployment-owned execution trust bundle.

``PV_EXECUTION_TRUST_BUNDLE_FILE`` is loaded once at production startup.
Callers never supply this bundle at dispatch time.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_dna.authority_v01 import AuthorityFormatError, validate_trust_bundle

EXECUTION_TRUST_BUNDLE_ENV = "PV_EXECUTION_TRUST_BUNDLE_FILE"
DISPATCH_WITNESS_KEY_ENV = "PV_DISPATCH_WITNESS_KEY"

REQUIRED_EXECUTION_USAGES = frozenset(
    {
        "execution_authorization_signer",
        "dispatch_witness_signer",
        "closure_signer",
    }
)


def load_execution_trust_bundle(path: str) -> dict[str, Any]:
    """Read, copy, and validate a deployment-owned execution trust bundle."""
    bundle_path = Path(path)
    if not bundle_path.is_file():
        raise RuntimeError(f"{EXECUTION_TRUST_BUNDLE_ENV} path does not exist: {path}")
    try:
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"{EXECUTION_TRUST_BUNDLE_ENV} is not readable JSON: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"{EXECUTION_TRUST_BUNDLE_ENV} must be a JSON object")
    return validate_execution_trust_bundle(raw)


def validate_execution_trust_bundle(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed unless EA-signer and dispatch-witness keys are present."""
    try:
        keys = validate_trust_bundle(bundle)
    except AuthorityFormatError as exc:
        raise RuntimeError(
            f"{EXECUTION_TRUST_BUNDLE_ENV} failed validation: {exc}"
        ) from exc
    present: set[str] = set()
    for key in keys.values():
        usages = key.get("usages") or []
        present.update(str(u) for u in usages)
    missing = REQUIRED_EXECUTION_USAGES - present
    if missing:
        raise RuntimeError(
            f"{EXECUTION_TRUST_BUNDLE_ENV} missing required key usages: "
            + ", ".join(sorted(missing))
        )
    # Defensive copy so a caller cannot mutate the pinned root after load.
    return json.loads(json.dumps(bundle, sort_keys=True))


def execution_trust_bundle_from_env() -> dict[str, Any] | None:
    path = os.getenv(EXECUTION_TRUST_BUNDLE_ENV, "")
    if not path:
        return None
    return load_execution_trust_bundle(path)
