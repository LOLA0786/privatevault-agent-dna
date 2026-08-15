# Brief: structural map + architecture decision records

Two deliverables. Do not merge them into one artifact — they have
different failure modes. The map goes stale silently, so it must be
generated. The records cannot be recovered from code, so they must be
written by a human who remembers why.

Repo discipline applies throughout: no claim without a named test, and
anything not backed by a test goes in docs/WHAT-WE-DO-NOT-CLAIM.md.

---

## Deliverable 1 — tools/gen_architecture.py

Generate a structural map from the code. Never hand-maintain it.

### Source of truth
Parse with `ast`, not grep. Grep on OWASP vocabulary has produced wrong
answers in this repo before; map from real import statements and real
test function names only.

### What to extract
For every file under `tests/`:
  - which `agent_dna.*` / `api.*` modules it imports
  - every `test_*` function name
  - the module-level docstring (tests here carry intent in the module
    docstring more often than per-function)

For every module under `agent_dna/` and `api/`:
  - which test files import it
  - which import zero test files  ← this is the interesting output

### What to emit
`architecture.html`, single file, no build step, same visual system as
`test-index.html` (paper/ink tokens, mono labels, hairline rules).

Four views:

1. **Enforcement path.** The ordered spine: identity → invariants →
   policy → approval → grants → limits → anomaly → permit mint →
   dispatch. Each stage shows the modules that implement it and the
   count of tests that import them. This is the diagram someone reads
   first; make it legible before making it complete.

2. **Coverage inversion.** Every module ranked by how many test files
   import it. Top of the list is the load-bearing code. Bottom — the
   zero-import modules — is the honest finding, and it must be rendered
   as prominently as the top, not tucked away.

3. **Clusters.** Test files grouped by shared module dependencies.
   Files that import no `agent_dna` module are genuinely isolated
   (spec/vector/schema tests) and belong in their own group labelled as
   such, not hidden.

4. **Cross-layer edges.** Where a single test imports modules from more
   than one enforcement stage. These are the composition tests —
   cross-agent correlation, exact-byte binding, the gateway. They are
   the ones that catch what per-stage checks cannot, and they should be
   visually distinct.

### Constraints
- stdlib only, no graphviz, no networkx, no npm
- must run in under 10 seconds
- gitignore the output; commit only the generator
- if a module or test cannot be parsed, list it as unparsed — never
  silently drop it

### Verify before claiming done
    python tools/gen_architecture.py
    python -m pytest --collect-only -q | tail -1
Total test count in the HTML must equal pytest's number exactly. If it
does not, the map is wrong and nothing else about it matters.

---

## Deliverable 2 — docs/adr/

One file per decision: `docs/adr/NNNN-short-slug.md`.

Audience is an engineer who joins in 2036, has never met anyone who
worked on this, and is about to change something they think is
redundant. Write for that person.

### Format
    # NNNN — <decision stated as a sentence>

    Status:     accepted | superseded by NNNN | proposed | open
    Date:       YYYY-MM-DD
    Commit:     <sha where this landed, if it landed>
    Pinned by:  <path::test_name>   ← the test that fails if this is undone

    ## What forced the decision
    The situation, honestly. Include the alternative that was rejected
    and why it was tempting. A decade later the alternative will look
    obviously better unless its cost is written down.

    ## The decision
    One paragraph. Present tense.

    ## What this costs us
    Every decision here bought something and paid for it. Name the price.
    An ADR with no cost section was not a real decision.

    ## What would make us revisit
    Concrete triggers, not "if requirements change."

### The `Pinned by` line is the point
If a decision has no test that fails when it is undone, it is not
enforced — it is a preference, and it will erode. Say so explicitly in
the ADR rather than inventing a test reference.

### Write these first
    0001  The enforcement boundary is the action, not the model
    0002  The decision path is deterministic and fail-closed
    0003  Authorization and execution are bound by action_digest (DRP 0.2)
    0004  Permits are single-use against a durable ledger
    0005  A permit burned by transport failure is not retried
    0006  INDETERMINATE is a first-class outcome, not an error
    0007  The execution trust bundle is deployment-pinned, not caller-supplied
    0008  The dispatch witness is signed after send, never before
    0009  A key may not both mint permits and witness them
    0010  PV_SECURE_PROFILE refuses PV_ALLOW_NO_AUTH rather than warning
    0011  Every claim is pinned to a named test, count enforced in CI
    0012  Python and Rust maintain CI parity
    0013  Open-core split: drp-spec Apache-2.0, runtime commercial

Plus one with status `open`:
    0014  Peer identity format for the production TLS sidecar
          The mint side computes the digest over a synthetic identifier
          (tls-spki:...). TlsHttpsSidecarTransport observes certificate
          DER. These do not match, and no code in the repo mints against
          real DER, so the production path has never completed a dispatch.
          Record both candidate formats and what each costs: full DER
          breaks every outstanding permit on certificate rotation; an
          SPKI hash survives rotation but binds less. Do not resolve this
          in the ADR — resolve it by running the path against a real TLS
          server, then supersede.

### Do not
- Do not write an ADR for anything that was never actually contested.
- Do not describe current behaviour. Code already does that, and better.
- Do not backfill a `Pinned by` reference that does not exist.
