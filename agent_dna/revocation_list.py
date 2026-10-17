"""Signed revocation list for receivers (grant revocation, part 2).

Part 1 (``grant_revocation``) suspends outstanding permits everywhere
PrivateVault controls. A receiving system that already holds a permit is a
separate trust domain, so PrivateVault publishes what it has revoked:

``pv-revocation-list/0.1``, signed with the same execution-authorization key
that signs permits (the receiver already pins it in its trust bundle), with
an explicit validity window::

    {spec, organisation_id, list_id, issued_at, next_update,
     revoked_authorizations: [execution_authorization_id, ...],
     suspended_agents: [agent id, ...],
     organisation_suspended: bool,
     signer_key_id, signature}

The receiver gate refuses a permit that is listed, whose subject agent is
suspended, or whose organisation is suspended. It **fails closed** when its
copy is missing or past ``next_update``: a receiver that cannot get a fresh
list stops admitting permits rather than quietly admitting revoked ones.
Older lists never replace newer ones (no rollback).

Permits are short-lived (minutes), so the list only carries authorizations
whose permit has not yet expired.
"""

from __future__ import annotations

import json
import threading
import urllib.request
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from nacl.exceptions import BadSignatureError

from .authority_v01 import (
    AuthorityFormatError,
    sign_document,
    validate_trust_bundle,
    verify_document_signature,
)

REVOCATION_LIST_SPEC = "pv-revocation-list/0.1"
_FIELDS = frozenset(
    {
        "spec",
        "organisation_id",
        "list_id",
        "issued_at",
        "next_update",
        "revoked_authorizations",
        "suspended_agents",
        "organisation_suspended",
        "signer_key_id",
        "signature",
    }
)
_SIGNER_USAGE = "execution_authorization_signer"

RECEIVER_PERMIT_REVOKED = "RECEIVER_PERMIT_REVOKED"
RECEIVER_REVOCATION_LIST_STALE = "RECEIVER_REVOCATION_LIST_STALE"


class RevocationListError(ValueError):
    """A revocation list that must not be trusted."""


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


# ---- issuing (PrivateVault side) ------------------------------------------


def build_revocation_list(
    store: Any,
    *,
    organisation_id: str,
    signing_key: Any,
    signer_key_id: str,
    validity: timedelta = timedelta(seconds=30),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign the current suspensions of this organisation for receivers."""
    now = now or datetime.now(UTC)
    rows, expiries = store.revocation_rows()
    authorizations: set[str] = set()
    agents: set[str] = set()
    org_suspended = False
    for kind, scope_id in rows:
        if kind == "authorization":
            expires = expiries.get(scope_id)
            if expires is None or _parse(expires) > now:
                authorizations.add(scope_id)
        elif kind == "agent":
            agents.add(scope_id)
        elif kind == "organisation" and scope_id == organisation_id:
            org_suspended = True
    document = {
        "spec": REVOCATION_LIST_SPEC,
        "organisation_id": organisation_id,
        "list_id": f"rl-{uuid.uuid4()}",
        "issued_at": _rfc3339(now),
        "next_update": _rfc3339(now + validity),
        "revoked_authorizations": sorted(authorizations),
        "suspended_agents": sorted(agents),
        "organisation_suspended": org_suspended,
        "signer_key_id": signer_key_id,
    }
    return sign_document(document, signing_key, signature_field="signature")


# ---- verifying and enforcing (receiver side) ------------------------------


class RevocationListCache:
    """The receiver's verified copy of the latest revocation list."""

    def __init__(self, trust_bundle: Mapping[str, Any]) -> None:
        self._keys = validate_trust_bundle(trust_bundle)
        self._organisation_id = trust_bundle["organisation_id"]
        self._lock = threading.Lock()
        self._current: dict[str, Any] | None = None

    @property
    def current(self) -> dict[str, Any] | None:
        return self._current

    def update(  # noqa: C901 - ordered refusal checklist
        self, document: Mapping[str, Any], *, now: datetime | None = None
    ) -> None:
        """Verify and install a list. Raises RevocationListError if untrusted."""
        now = now or datetime.now(UTC)
        if not isinstance(document, Mapping) or set(document) != _FIELDS:
            raise RevocationListError("revocation list field set mismatch")
        doc = dict(document)
        if doc["spec"] != REVOCATION_LIST_SPEC:
            raise RevocationListError("unsupported revocation list spec")
        if doc["organisation_id"] != self._organisation_id:
            raise RevocationListError("revocation list is for another organisation")
        key = self._keys.get(doc["signer_key_id"])
        if key is None or _SIGNER_USAGE not in key["usages"]:
            raise RevocationListError("revocation list signer is not trusted")
        try:
            valid = verify_document_signature(
                doc, signature_field="signature", public_key=key["public_key"]
            )
        except (AuthorityFormatError, BadSignatureError, ValueError) as exc:
            raise RevocationListError(f"invalid signature: {exc}") from exc
        if not valid:
            raise RevocationListError("invalid revocation list signature")
        try:
            issued, nxt = _parse(doc["issued_at"]), _parse(doc["next_update"])
        except (TypeError, ValueError) as exc:
            raise RevocationListError("bad revocation list timestamps") from exc
        if nxt <= issued:
            raise RevocationListError("next_update must be after issued_at")
        for name in ("revoked_authorizations", "suspended_agents"):
            if not isinstance(doc[name], list) or not all(
                isinstance(x, str) for x in doc[name]
            ):
                raise RevocationListError(f"{name} must be a list of strings")
        if not isinstance(doc["organisation_suspended"], bool):
            raise RevocationListError("organisation_suspended must be a boolean")
        with self._lock:
            if self._current is not None and issued < _parse(
                self._current["issued_at"]
            ):
                raise RevocationListError("older than the installed list (rollback)")
            self._current = doc

    def refresh(self, url: str, *, api_key: str, timeout: float = 5.0) -> None:
        """Fetch ``GET /v1/revocations`` and install it if it verifies."""
        request = urllib.request.Request(url, headers={"X-API-Key": api_key})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            self.update(json.loads(response.read().decode("utf-8")))

    def refusal(
        self,
        authorization: Mapping[str, Any],
        *,
        now: datetime,
        clock_skew: timedelta = timedelta(0),
    ) -> tuple[str, str] | None:
        """(reason_code, detail) if this permit must be refused, else None."""
        current = self._current
        if current is None:
            return RECEIVER_REVOCATION_LIST_STALE, "no revocation list installed"
        if now - clock_skew >= _parse(current["next_update"]):
            return (
                RECEIVER_REVOCATION_LIST_STALE,
                f"revocation list expired at {current['next_update']}",
            )
        if current["organisation_suspended"]:
            return RECEIVER_PERMIT_REVOKED, "organisation suspended"
        if authorization.get("execution_authorization_id") in set(
            current["revoked_authorizations"]
        ):
            return RECEIVER_PERMIT_REVOKED, "permit revoked"
        action = authorization.get("action")
        agent = action.get("subject_key_id") if isinstance(action, Mapping) else None
        if agent in set(current["suspended_agents"]):
            return RECEIVER_PERMIT_REVOKED, f"agent {agent} suspended"
        return None
