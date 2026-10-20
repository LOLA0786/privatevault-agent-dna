"""The evidence a permit cites is the server's, not the caller's (ADR 0026).

A permit carries four references: ``policy_bundle_digest``,
``authority_receipt_digest``, ``state_snapshot_digest`` and
``obligations_digest``. Before this module ``/v1/authorize`` copied whatever
the caller sent into the signed permit (external review, 19 October 2026,
finding 3), so a signature over them proved nothing about what was checked.

Now the server fixes all four when it decides and seals them into the
decision record, inside the control-posture evidence item that callers
cannot write (``agent_dna.control_posture``):

``policy_bundle_digest``
    The decision configuration this server loaded at start-up: the policy
    source (the policy file's bytes, or the OPA endpoint, policy path and
    bundle bytes), the grants file's bytes and the operations registry
    digest, and the approval policy file's bytes when one is set (ADR 0031).
    For an OPA endpoint it names where the policy lives, not what the remote
    policy says.
``authority_receipt_digest``
    The grant the decision ran under, as configured (id, agent, capability,
    granted_by, expiry, budget), or ``NONE_DIGEST`` without a grant.
``state_snapshot_digest`` and ``obligations_digest``
    ``NONE_DIGEST``. The API evaluates no enterprise state snapshot and
    attaches no obligations, so its signature does not claim either.

``PV_PERMIT_EVIDENCE=server`` (the secure-profile default): at mint the
sealed values go into the permit. A caller value that differs is refused,
and a mint on a server whose decision configuration differs from the one
that decided is refused; decide again.

``PV_PERMIT_EVIDENCE=caller`` (the default without the secure profile, and
refused with it): a value the caller sends is signed as given, as before;
an omitted one is the sealed value. The mint response lists the fields that
are the caller's assertions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna.control_posture import posture_from_evidence

PERMIT_EVIDENCE_KEY = "permit_evidence"
POLICY_BUNDLE_SPEC = "pv-policy-bundle/0.1"
GRANT_SNAPSHOT_SPEC = "pv-grant-snapshot/0.1"
# "Nothing here": the same all-zero digest permits already use for "no
# approval". A permit with it does not claim the reference was checked.
NONE_DIGEST = "sha256:" + "0" * 64

FIELDS = (
    "policy_bundle_digest",
    "authority_receipt_digest",
    "state_snapshot_digest",
    "obligations_digest",
)

SERVER = "server"
CALLER = "caller"
MODES = (SERVER, CALLER)


class PermitEvidenceError(ValueError):
    """A configured input cannot be read, or the mode is invalid."""


def _digest(document: Any) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _file_digest(path: str | None, label: str) -> str | None:
    if not path:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PermitEvidenceError(f"{label}: cannot read {path}: {exc}") from exc
    return "sha256:" + hashlib.sha256(data).hexdigest()


def policy_bundle_digest(
    env: Mapping[str, str], *, operations_digest: str | None
) -> str:
    """Digest of the decision configuration named by ``env``.

    The policy file wins over OPA, as in the composition root.
    """
    policy_file = env.get("PV_POLICY_FILE") or None
    opa_endpoint = env.get("PV_OPA_ENDPOINT") or None
    if policy_file:
        policy: dict[str, Any] | None = {
            "file": _file_digest(policy_file, "PV_POLICY_FILE")
        }
    elif opa_endpoint:
        policy = {
            "opa_endpoint": opa_endpoint,
            "opa_policy_path": env.get("PV_OPA_POLICY_PATH") or "agent/governance",
            "opa_bundle": _file_digest(env.get("PV_OPA_BUNDLE"), "PV_OPA_BUNDLE"),
        }
    else:
        policy = None
    document: dict[str, Any] = {
        "spec": POLICY_BUNDLE_SPEC,
        "policy": policy,
        "grants": _file_digest(env.get("PV_GRANTS_FILE"), "PV_GRANTS_FILE"),
        "operations": operations_digest,
    }
    # ADR 0031: who may approve is decision configuration too. Added only
    # when set, so deployments without one keep their digest.
    approval_policy = _file_digest(
        env.get("PV_APPROVAL_POLICY_FILE"), "PV_APPROVAL_POLICY_FILE"
    )
    if approval_policy is not None:
        document["approval_policy"] = approval_policy
    return _digest(document)


def grant_digest(snapshot: Mapping[str, Any] | None) -> str:
    """The configured grant a decision ran under, or ``NONE_DIGEST``."""
    if snapshot is None:
        return NONE_DIGEST
    return _digest({"spec": GRANT_SNAPSHOT_SPEC, **snapshot})


def decided_evidence(
    *, policy_bundle: str, grant: Mapping[str, Any] | None
) -> dict[str, str]:
    """The four references fixed when a decision is made."""
    return {
        "policy_bundle_digest": policy_bundle,
        "authority_receipt_digest": grant_digest(grant),
        "state_snapshot_digest": NONE_DIGEST,
        "obligations_digest": NONE_DIGEST,
    }


def sealed_evidence(record: Mapping[str, Any]) -> dict[str, str] | None:
    """The references sealed in a decision record, or None if it has none."""
    posture = posture_from_evidence(record.get("evidence"))
    if posture is None:
        return None
    sealed = posture.get(PERMIT_EVIDENCE_KEY)
    if not isinstance(sealed, dict):
        return None
    if not all(isinstance(sealed.get(name), str) for name in FIELDS):
        return None
    return {name: str(sealed[name]) for name in FIELDS}


@dataclass(frozen=True)
class EvidenceMismatch:
    field: str
    supplied: str
    sealed: str


def first_mismatch(
    sealed: Mapping[str, str], supplied: Mapping[str, str | None]
) -> EvidenceMismatch | None:
    """The first caller value that differs from the sealed one. A caller may
    omit a value; it may not replace one."""
    for name in FIELDS:
        value = supplied.get(name)
        if value is not None and value != sealed[name]:
            return EvidenceMismatch(name, value, sealed[name])
    return None


def evidence_mode(env: Mapping[str, str], *, secure: bool) -> str:
    """``PV_PERMIT_EVIDENCE``: ``server`` (default under the secure profile)
    or ``caller`` (default otherwise; refused under the secure profile)."""
    raw = (env.get("PV_PERMIT_EVIDENCE") or "").strip().lower()
    if not raw:
        return SERVER if secure else CALLER
    if raw not in MODES:
        raise PermitEvidenceError(
            f"PV_PERMIT_EVIDENCE must be one of {', '.join(MODES)}, not {raw!r}"
        )
    if secure and raw == CALLER:
        raise PermitEvidenceError(
            "PV_SECURE_PROFILE=1 refuses PV_PERMIT_EVIDENCE=caller: a permit "
            "must not sign references the server did not check"
        )
    return raw
