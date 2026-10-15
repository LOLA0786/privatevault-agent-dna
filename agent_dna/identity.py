"""Agent identity normalization (ADR 0021, PR 1 of the lineage work).

Every comparison that decides "is this the same agent?" -- maker != checker,
requester != approver, cycle detection -- must compare one canonical form.
Otherwise ``treasury-agent`` and ``Treasury-Agent`` (or a fullwidth or
ligature variant) are two identities to the invariant and one identity to a
human reading the audit trail.

Two levels:

* :func:`fold_agent_id` -- lenient, total. NFKC, casefold, NFKC again, strip.
  Used wherever an existing identifier must be compared and refusing it would
  break deployments (approval separation of duties, CABI windows, loop
  graphs). Never raises.
* :func:`normalize_agent_id` -- strict. The fold, plus refusal of control,
  format and separator characters, surrounding whitespace and over-long ids.
  Used for new identifiers the server itself mints (lineage, delegation).

``is_strict_ascii_agent_id`` is the secure-profile rule: NFKC does not fold
confusables (Cyrillic "а" vs Latin "a"), so high-assurance deployments
restrict ids to a small ASCII alphabet.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

MAX_AGENT_ID_LENGTH = 128
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_STRICT_ASCII = re.compile(r"[a-z0-9][a-z0-9._:@-]{0,127}\Z")


class AgentIdentityError(ValueError):
    """An agent id that cannot be given a single canonical form."""


def fold_agent_id(value: str) -> str:
    """Canonical comparison form. Total: never raises on a str."""
    text = unicodedata.normalize("NFKC", str(value))
    text = unicodedata.normalize("NFKC", text.casefold())
    return text.strip()


def normalize_agent_id(value: object) -> str:
    """Strict canonical form for identifiers the server mints or binds."""
    if not isinstance(value, str):
        raise AgentIdentityError("agent id must be a string")
    if value != value.strip():
        raise AgentIdentityError("agent id has leading or trailing whitespace")
    for char in value:
        if unicodedata.category(char) in _REFUSED_CATEGORIES:
            raise AgentIdentityError(
                f"agent id contains a refused character U+{ord(char):04X}"
            )
    folded = fold_agent_id(value)
    if not folded:
        raise AgentIdentityError("agent id is empty")
    if len(folded) > MAX_AGENT_ID_LENGTH:
        raise AgentIdentityError(
            f"agent id exceeds {MAX_AGENT_ID_LENGTH} characters after folding"
        )
    return folded


def is_strict_ascii_agent_id(value: str) -> bool:
    """Secure-profile alphabet: lowercase ASCII, digits and ``._:@-``."""
    return bool(_STRICT_ASCII.match(value))


def identity_collisions(names: Iterable[str]) -> list[tuple[str, ...]]:
    """Groups of DISTINCT raw names that fold to the same identity.

    The same raw name appearing twice (e.g. a rotated key) is not a
    collision; ``alice`` and ``Alice`` are.
    """
    groups: dict[str, set[str]] = {}
    for name in names:
        groups.setdefault(fold_agent_id(name), set()).add(name)
    return sorted(tuple(sorted(raw)) for raw in groups.values() if len(raw) > 1)
