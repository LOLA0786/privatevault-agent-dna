"""How long a sealed ALLOW may still be turned into a permit.

A decision is made at one moment, under authority that has its own end: a
signed human approval expires, a capability grant expires. Minting later
must not stretch that authority (external review, 19 October 2026,
finding 2). The deadline is the earliest of:

* the decision's own mint window: the record's sealed, server-set
  ``timestamp`` plus ``PV_DECISION_MINT_WINDOW_SECONDS``. The caller's
  action timestamp is never used;
* for an approval-triggered ALLOW, the verified approval artifact's
  ``expires_at``, stored by the server beside the approval's single-use
  claim (``approval_consume.not_after``);
* for a grant-backed ALLOW, the grant's ``expires_at`` in the operator's
  registry, looked up by the grant id sealed in the record.

``/v1/authorize`` refuses at or after the deadline and caps the permit's
``expires_at`` at it, so the sidecar and the receiver, which already refuse
an expired permit, enforce the same end. A deadline that cannot be
established (an approval with no stored expiry, a grant id the registry no
longer knows) refuses: unknown authority is not authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .approval_bridge import TRIGGERED_BY_APPROVAL

DECISION_WINDOW = "decision_window"
APPROVAL_EXPIRY = "approval_expiry"
GRANT_EXPIRY = "grant_expiry"

DECISION_MINT_WINDOW_SECONDS_DEFAULT = 300
DECISION_MINT_WINDOW_SECONDS_MIN = 1
DECISION_MINT_WINDOW_SECONDS_MAX = 3600


class AuthorityUnknownError(ValueError):
    """The authority behind a decision cannot be bounded; refuse to mint."""


@dataclass(frozen=True)
class AuthorityDeadline:
    not_after: datetime
    basis: str  # which limit is the earliest

    def expired_at(self, now: datetime) -> bool:
        return now >= self.not_after


def _parse_rfc3339(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp without a timezone")
    return parsed.astimezone(UTC)


def authority_deadline(
    record: dict[str, Any],
    *,
    decision_window_seconds: int,
    approval_not_after: Callable[[str], str | None],
    grant_expires_at: Callable[[str], float | None],
) -> AuthorityDeadline:
    """The earliest end of the authority behind a sealed decision.

    ``approval_not_after(digest)`` returns the stored RFC 3339 expiry of a
    consumed approval, or None if none is stored. ``grant_expires_at(id)``
    returns a grant's expiry in epoch seconds (None: never expires) and
    raises ``KeyError`` for a grant the registry does not know.
    """
    stamp = record.get("timestamp")
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
        raise AuthorityUnknownError("sealed decision has no server timestamp")
    decided_at = datetime.fromtimestamp(float(stamp), UTC)
    limits = [
        (decided_at + timedelta(seconds=decision_window_seconds), DECISION_WINDOW)
    ]

    ref = record.get("approval_ref")
    if record.get("triggered_by") == TRIGGERED_BY_APPROVAL:
        if not isinstance(ref, str) or not ref:
            raise AuthorityUnknownError("approval-triggered ALLOW names no approval")
        stored = approval_not_after(ref)
        if not stored:
            raise AuthorityUnknownError(
                "no stored expiry for the approval behind this decision"
            )
        try:
            limits.append((_parse_rfc3339(stored), APPROVAL_EXPIRY))
        except ValueError as exc:
            raise AuthorityUnknownError(
                f"stored approval expiry unreadable: {exc}"
            ) from exc
    elif isinstance(ref, str) and ref:
        try:
            expires = grant_expires_at(ref)
        except KeyError:
            raise AuthorityUnknownError(
                f"the grant behind this decision is no longer configured ({ref})"
            ) from None
        if expires is not None:
            limits.append((datetime.fromtimestamp(float(expires), UTC), GRANT_EXPIRY))

    not_after, basis = min(limits, key=lambda item: item[0])
    return AuthorityDeadline(not_after=not_after, basis=basis)
