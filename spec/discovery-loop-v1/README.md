# PrivateVault Discovery Loop v1

This contract covers the offline scientific loop for decision-security
controls:

`mine sealed evidence -> run additive shadow experiments -> evaluate -> rank`

It does **not** authorize or install policy. A `PROPOSE` disposition means that
the candidate has enough committed evidence to become a human-reviewed pull
request. Online L0-L5 enforcement remains deterministic and unchanged; learned
L6 signals remain advisory-only.

`adversarial-row.schema.json` defines the committed experiment corpus. Labels
describe the corpus, not independent ground truth. `report.schema.json` defines
the hash-sealed run report. The independent standard-library verifier is
`tools/verify_discovery.py`.

The stable agent security loop detector may be supplied as a hard structural
probe. `BLOCK` rejects candidates and `REVIEW` prevents `PROPOSE`. Experimental
Hodge and authority-reachability analyses remain quarantined until stable wire
schemas and independent verifiers exist.

Consumers must reject unknown fields. Digests provide content identity and
tamper evidence; they are not signatures.

`vectors/no-change-report.json` is the canonical zero-candidate vector used by
the independent verifier and sealed proof-of-run gate.
