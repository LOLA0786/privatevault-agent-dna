# Policy change gate — putting a control change through code review

A rule change is the scariest operation in a regulated enterprise
because nobody can answer *what will this break?* before it ships.
This gate answers it in the pull request.

## What a policy repository looks like
policies/
wire-limits.json      # rules + their assertions
dlp.json
corpus.jsonl          # committed decision corpus (scrubbed, reviewed)
.github/workflows/policy-gate.yml

## A rule that states its own intent

```json
{
  "policies": [{
    "id": "WIRE-CAP-200K",
    "capability": "payments.initiate_wire",
    "outcome": "block",
    "reason": "wires above 200k require manual release",
    "condition": {"field": "arguments.amount", "operator": ">",
                  "value": 200000}
  }],
  "assertions": [
    {"name": "blocks a 250k wire", "capability": "payments.initiate_wire",
     "arguments": {"amount": 250000}, "expect": "block"},
    {"name": "allows a 5k wire", "capability": "payments.initiate_wire",
     "arguments": {"amount": 5000}, "expect": "allow"}
  ]
}
```

Assertions are stripped before parsing, so the rule set stays a
portable policy document.

## Two history sources

**Fixture (CI default).** `--fixture policies/corpus.jsonl` — a
committed corpus of past decisions. No production access, no data
retention question, works in a fork PR. Start here.

**Sealed history.** `--history-db … --replay-fields amount,currency`
— replay against real decisions via the opt-in field-scoped sidecar
(see POLICY-REPLAY.md). Use in a staging/internal runner where that
store is reachable.

## Exit contract

| code | meaning | CI |
|---|---|---|
| 0 | assertions pass, divergence within budget | merge |
| 1 | assertion failed or budget exceeded | block |
| 2 | malformed rule or bad configuration | block, fix the file |

A malformed rule is deliberately distinguishable from a risky one.

## Budgets are acknowledgements, not thresholds

`--max-new-blocks 211` doesn't make 211 acceptable — it makes someone
type 211 into a reviewable diff. `--max-new-allows` defaults to 0
because a rule that *relaxes* enforcement is the direction that
deserves the most scrutiny.

## What this does not do

The gate is only as good as the corpus. A fixture that doesn't contain
250k wires can't tell you a 200k cap would have blocked them. Corpus
coverage is the customer's responsibility and should be reviewed like
test coverage. Forward-looking shadow mode has no such limit — it sees
live traffic in full.
