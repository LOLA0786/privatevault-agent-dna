# 0029: Routine reads are indexed queries, one page at a time

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/test_indexed_reads.py::test_indexed_reads_match_the_full_graph;
            tests/test_indexed_reads.py::test_api_reads_never_load_the_whole_ledger;
            tests/test_indexed_reads.py::test_tampered_row_is_refused;
            tests/test_indexed_reads.py::test_reads_stay_within_the_callers_agent;
            tests/test_indexed_reads.py::test_sqlite_pages_use_an_index

## What forced the decision
An external review (19 October 2026, finding 5) found that in multi-writer
mode (PostgreSQL, or `PV_MULTI_WRITER=1`) every routine read called
`load_graph()`. That covered records by agent, blocked, divergent, lineage
and the ownership check behind `/v1/outcome`. `load_graph()` loads and
verifies every record in the ledger, so the cost of each call grew with the
ledger.

## The decision
- Both ledgers answer routine reads with SQL (`agent_dna/ledger_reads.py`):
  - **Lists:** `decision_rows` returns one page of decisions, filtered by
    agent, by verdict, or to the divergent set. The divergent set is
    BLOCKed decisions whose execution row reports `ok`; it is a join on
    the existing unique index on `decision_ref`.
  - **Lineage:** `decision_lineage_rows` gets a decision and all its
    ancestors in one recursive query.
  - **Ownership:** `get_decision` is a single-row lookup.
- Pages use keyset pagination on the ledger's insertion sequence: oldest
  first, `limit` 1 to 1000 (default 100). Each response has a
  `next_cursor`, which is null on the last page. Two partial indexes,
  `(agent_id, seq)` and `(decision, seq)` on decision rows, are created at
  start-up on both stores.
- Every record returned is rebuilt and its seal checked. A lineage's parent
  links are checked too. A tampered or broken row is a 500 ("a stored
  record failed verification") and is never served, as `load_graph()`
  ensured before.
- The API uses these whenever the recorder has a store. That is both
  ledgers, in single-writer mode as well. The in-memory graph is the
  fallback only without a store.
- Whole-ledger verification stays an explicit audit call (`GET
  /v1/verify`), as do exports and backups.

## What this costs us
- `/v1/records`, `/v1/blocked` and `/v1/divergent` return the first 100
  records unless `limit` or `cursor` is given. A client that expected the
  whole list must follow `next_cursor`.
- A lineage is the agent's whole chain, because a decision's parent is the
  agent's previous decision. Since the follow-up review (20 October 2026)
  it is paged like the lists: at most `limit` records per request, newest
  page first, `next_cursor` naming the next older decision. The page size
  bounds the recursive query; there is no separate depth constant.
- Creating the two indexes on a large existing PostgreSQL ledger happens at
  start-up under the schema lock (not `CONCURRENTLY`). For a very large
  ledger, create them by hand first; the statements are in
  `READ_INDEXES`.

## What would make us revisit
Filters that page on something other than insertion order (time ranges,
capability), or reads that must be served from a replica.
