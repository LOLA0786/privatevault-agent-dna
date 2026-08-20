# Phase 1 follow-ups (tracked, not fixed)

These findings were recorded during `fix/pv-critical-semantics`.
They are **not** in scope for Phase 1. Do not treat this file as a
fix. No administrative recovery endpoint is included here either
(ADR 0016: remint recovery remains deferred).

## 1. Durable grant-budget accounting

**Release blocker** for any monetary/budget claim.

- `GrantRegistry.spent` is in-process memory (`agent_dna/grants.py`).
- Loading the same grants file after process restart creates grants
  with zero spend.
- Check-then-increment is not a durable exclusive claim.

**Schedule:** branch `fix/durable-grant-budgets` immediately after
Phase 1.

**Required future tests:** restart, multi-process, concurrent spend,
rollback, and database failure. A passing unit test in one process is
not sufficient.

## 2. Metrics authentication mismatch

**Code:** `GET /metrics` in `api/server.py` has no authentication
dependency. A process with API keys enabled still serves Prometheus
text to an unauthenticated client (confirmed 200 with auth on).

**Docs disagree with each other and with the code:**

| Location | Stated auth |
|---|---|
| `docs/API-SURFACE.md` Platform ops table | open |
| `docs/API-SURFACE.md` Operational section | `audit` or `full` |
| Implementation | open |

**Exact fields exposed on this run** (unauthenticated `GET /metrics`,
API keys enabled, `prometheus_client` present, no decide traffic yet):

Declared application metrics:

- `pv_decisions_total` (HELP/TYPE present; samples appear after decisions)
- `pv_blocks_total` (HELP/TYPE present; `reason` label after blocks)
- `pv_decide_latency_seconds_bucket{le=...}`
- `pv_decide_latency_seconds_count`
- `pv_decide_latency_seconds_sum`
- `pv_decide_latency_seconds_created`
- `pv_ready`

Default collectors observed on the same body:

- `python_gc_objects_collected_total{generation=...}`
- `python_gc_objects_uncollectable_total{generation=...}`
- `python_gc_collections_total{generation=...}`
- `python_info{implementation,major,minor,patchlevel,version}`

Fallback if `prometheus_client` is absent: `pv_decisions_total{verdict}`
and `pv_ready` only.

`pv_blocks_total{reason}` can carry truncated internal reason strings.

**Proposed contract (not implemented):** either

1. require `audit` or `full` on `/metrics` and bind scrapes through a
   dedicated scrape key, or
2. keep `/metrics` deliberately unauthenticated, document it as open,
   and network-restrict it; put operator JSON behind `/v1/ops/summary`
   only.

Do not ship both “open” and “audit/full” for the same route.

## 3. Dashboard dependency vulnerability

Commands (no upgrade performed):

```bash
npm --prefix dashboard audit --json
npm --prefix dashboard audit --omit=dev --json
```

| Field | Result |
|---|---|
| Package | `nanoid` **3.3.17** |
| Severity | high (GHSA-2v37-7h3g-55p8, CWE-835) |
| Affected range | `<3.3.18` |
| Path | `vite@8.1.0` → `postcss@8.5.25` → `nanoid@3.3.17` |
| Production/dev | **dev** (`dev: true` in the lockfile; `npm audit --omit=dev` reports **0** vulnerabilities) |
| Direct dependency | no |
| `fixAvailable` | true (do not force-upgrade in this branch) |

Production dashboard dependencies (`react`, `react-dom`) were not in
the advisory path. Remediation belongs in a controlled lockfile bump
of the Vite/PostCSS toolchain, not an unmanaged `npm audit fix --force`.
