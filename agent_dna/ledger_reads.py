"""Routine reads answered from the store, one page at a time (ADR 0029).

Before this module every multi-writer read (records by agent, blocked,
divergent, lineage, and the ownership check behind ``/v1/outcome``) called
``load_graph()``, which loads and verifies every record in the ledger; cost
grew with the ledger (external review, 19 October 2026, finding 5).

The stores now answer these with indexed SQL (``decision_rows``,
``get_decision``, one recursive query for a lineage) and keyset pagination
on the ledger's insertion sequence.
Every record returned is rebuilt and its seal checked here, so a tampered
row is refused rather than served, as ``load_graph`` did. Whole-ledger
verification stays an explicit audit call (``GET /v1/verify``).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agent_dna.decision_record import DecisionRecord

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
# A lineage is the agent's chain of decisions, so it can be long; the bound
# only stops a cycle or a corrupt parent pointer from recursing forever.
MAX_LINEAGE_DEPTH = 10_000_000


class LedgerIntegrityError(ValueError):
    """A stored record failed its seal check, or its lineage is broken."""


class CursorError(ValueError):
    """A page cursor that this ledger did not issue."""


def decision_from_dict(d: dict[str, Any]) -> DecisionRecord:
    """Rebuild a stored decision and check its seal."""
    data = dict(d)
    record_hash = data.pop("record_hash", None)
    data.pop("kind", None)
    protocol_version = data.pop("protocol_version", None)
    if protocol_version is None or record_hash is None:
        raise LedgerIntegrityError("stored decision lacks protocol_version or hash")
    try:
        record = DecisionRecord(protocol_version=protocol_version, **data)
    except (TypeError, ValueError) as exc:
        raise LedgerIntegrityError(f"stored decision is malformed: {exc}") from exc
    record.record_hash = record_hash
    if not record.verify():
        raise LedgerIntegrityError(
            f"stored decision {record.decision_id} failed its seal check"
        )
    return record


def decision_from_body(body: str) -> DecisionRecord:
    return decision_from_dict(json.loads(body))


def decode_cursor(cursor: str | None) -> int:
    """The ledger sequence a page starts after (0: from the beginning)."""
    if cursor is None or cursor == "":
        return 0
    if not cursor.isdigit() or len(cursor) > 18:
        raise CursorError("cursor is not one this API issued")
    return int(cursor)


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_PAGE_SIZE
    if limit < 1 or limit > MAX_PAGE_SIZE:
        raise CursorError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
    return limit


@dataclass(frozen=True)
class Page:
    records: list[DecisionRecord]
    next_cursor: str | None


def page_from_rows(rows: Sequence[tuple[int, str]], limit: int) -> Page:
    """``rows`` was fetched with ``limit + 1``: one extra row says whether
    another page exists."""
    shown = rows[:limit]
    records = [decision_from_body(body) for _seq, body in shown]
    more = len(rows) > limit
    return Page(records, str(shown[-1][0]) if more and shown else None)


def lineage_query(
    *, placeholder: str, parent_of: str, max_depth: int = MAX_LINEAGE_DEPTH
) -> str:
    """One recursive query for a decision and all its ancestors, deepest
    ancestor first. ``parent_of`` is the dialect's expression for a row's
    ``parent_decision`` given the alias (``{t}``)."""
    p = placeholder
    return (
        "WITH RECURSIVE chain(body, parent, depth) AS ("
        f" SELECT body, {parent_of.format(t='records')}, 0 FROM records"
        f" WHERE record_id = {p} AND kind = 'decision'"
        " UNION ALL"
        f" SELECT r.body, {parent_of.format(t='r')}, c.depth + 1"
        " FROM records r JOIN chain c ON r.record_id = c.parent"
        f" AND r.kind = 'decision' WHERE c.depth < {int(max_depth)}"
        ") SELECT body FROM chain ORDER BY depth DESC"
    )


def lineage_from_rows(bodies: Sequence[str], decision_id: str) -> list[DecisionRecord]:
    """Root-to-node path from the recursive query's rows, every record's
    seal and every parent link checked. KeyError if the decision is unknown."""
    if not bodies:
        raise KeyError(decision_id)
    path = [decision_from_body(body) for body in bodies]
    if path[-1].decision_id != decision_id:
        raise LedgerIntegrityError(f"lineage of {decision_id} ends elsewhere")
    if path[0].parent_decision is not None:
        raise LedgerIntegrityError(
            f"lineage of {decision_id} does not reach a root: parent "
            f"{path[0].parent_decision} is missing or the chain is too deep"
        )
    for parent, child in zip(path, path[1:], strict=False):
        if child.parent_decision != parent.decision_id:
            raise LedgerIntegrityError(f"broken parent link at {child.decision_id}")
    return path


# Partial indexes that make each page an index range scan (both stores).
READ_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_decisions_agent_seq
    ON records(agent_id, seq) WHERE kind = 'decision';
CREATE INDEX IF NOT EXISTS idx_decisions_verdict_seq
    ON records(decision, seq) WHERE kind = 'decision';
"""


def decision_rows_query(
    *,
    placeholder: str,
    execution_ok: str,
    agent_id: str | None,
    verdict: str | None,
    divergent: bool,
    after_seq: int,
    limit: int,
) -> tuple[str, tuple[Any, ...]]:
    """SQL for one page of decisions, oldest first, keyed on ``seq``.

    ``placeholder`` is the driver's parameter marker; ``execution_ok`` the
    dialect's test that an execution row ``e`` reports status ok.
    ``divergent``: BLOCKed decisions whose executor reported ``ok`` anyway
    (as ``DecisionGraph.find_divergent``).
    """
    p = placeholder
    where = ["d.kind = 'decision'", f"d.seq > {p}"]
    params: list[Any] = [after_seq]
    join = ""
    if agent_id is not None:
        where.append(f"d.agent_id = {p}")
        params.append(agent_id)
    if divergent:
        verdict = "block"
        join = (
            " JOIN records e ON e.kind = 'execution' "
            f"AND e.decision_ref = d.record_id AND {execution_ok}"
        )
    if verdict is not None:
        where.append(f"d.decision = {p}")
        params.append(verdict)
    sql = (
        f"SELECT d.seq, d.body FROM records d{join} WHERE "
        + " AND ".join(where)
        + f" ORDER BY d.seq LIMIT {p}"
    )
    params.append(limit + 1)
    return sql, tuple(params)
