#!/usr/bin/env python3
"""Independent verifier for pv-validation/1 reports.

Standard library only, zero dependency on the privatevault codebase --
same trust model as tools/verify_records.py. An auditor runs this
against a report file and gets PASS/FAIL per check.

Checks:
  1. seal        report_hash == sha256(canonical(body))
  2. format      body.format == "pv-validation/1"
  3. expiry      expires_at present; warns (not fails) if in the past
  4. counts      n == n_pos + n_neg; every segment table's n sums to n
  5. identity    global.auc == within + between contributions (1e-9)
  6. shares      within_pair_share + between_pair_share == 1 (1e-9)
  7. honesty     score.type == "ranking"  =>  calibration is null
  8. safeguards  any segment with n < min_samples has no point metrics
  9. labels      dataset.label_source == "independent" with a note

Exit code 0 iff all hard checks pass.
"""

import hashlib
import json
import sys
import time

TOL = 1e-9


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def verify(path: str) -> int:  # noqa: C901 — flat checklist, mirrors verify_records.py
    failures = []
    warnings = []

    try:
        envelope = json.loads(open(path, encoding="utf-8").read())
        body = envelope["body"]
        claimed = envelope["report_hash"]
    except Exception as e:
        print(f"FAIL  unreadable envelope: {e}")
        return 1

    # 1. seal
    actual = hashlib.sha256(canonical(body).encode()).hexdigest()
    if actual != claimed:
        failures.append(
            f"seal: hash mismatch (claimed {claimed[:12]}…, actual {actual[:12]}…)"
        )

    # 2. format
    if body.get("format") != "pv-validation/1":
        failures.append(f"format: {body.get('format')!r}")

    # 3. expiry
    exp = body.get("expires_at")
    if exp is None:
        failures.append("expiry: expires_at missing")
    elif exp < time.time():
        warnings.append("report is EXPIRED (integrity still verifiable)")

    ds = body.get("dataset", {})
    n = ds.get("n")

    # 4. counts
    if ds.get("n_pos", -1) + ds.get("n_neg", -1) != n:
        failures.append("counts: n_pos + n_neg != n")
    for name, table in (body.get("segments") or {}).items():
        total = sum(row.get("n", 0) for row in table)
        if total != n:
            failures.append(f"counts: segments.{name} sums to {total}, n={n}")

    # 5 & 6. decomposition identity
    g = body.get("global")
    if g:
        s = g["auc_within_contribution"] + g["auc_between_contribution"]
        if abs(s - g["auc"]) > TOL:
            failures.append(f"identity: within+between={s!r} != auc={g['auc']!r}")
        sh = g["within_pair_share"] + g["between_pair_share"]
        if abs(sh - 1.0) > TOL:
            failures.append(f"shares: pair shares sum to {sh!r}")

    # 7. ranking honesty
    stype = body.get("score", {}).get("type")
    if stype not in ("ranking", "probability"):
        failures.append(f"score.type invalid: {stype!r}")
    if stype == "ranking" and body.get("calibration") is not None:
        failures.append("honesty: calibration metrics present on a ranking score")

    # 8. safeguards
    min_n = (body.get("safeguards") or {}).get("min_samples")
    if min_n is None:
        failures.append("safeguards: min_samples missing")
    else:
        for name, table in (body.get("segments") or {}).items():
            for row in table:
                if row.get("n", 0) < min_n and (
                    row.get("auc") is not None or row.get("prevalence") is not None
                ):
                    failures.append(
                        f"safeguards: segments.{name} key={row.get('key')!r} "
                        f"n={row.get('n')} < min_samples yet reports metrics"
                    )

    # 9. label source
    if ds.get("label_source") != "independent":
        failures.append(f"labels: label_source={ds.get('label_source')!r}")
    if not (ds.get("label_source_note") or "").strip():
        failures.append("labels: label_source_note empty")

    for w in warnings:
        print(f"WARN  {w}")
    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        print(f"\nVERDICT: FAIL ({len(failures)} failure(s))")
        return 1
    print(
        "VERDICT: PASS (seal, counts, decomposition identity, "
        "ranking honesty, safeguards, label source)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(verify(sys.argv[1]))
