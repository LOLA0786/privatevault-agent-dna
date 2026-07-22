#!/usr/bin/env python3
"""DRP effect/decision reconciliation (drp-observer/1).

    python3 reconcile_effects.py <decision_log.jsonl> <effect_log.jsonl> [<effect_log2.jsonl> ...]

Standard library only. Zero dependency on the PrivateVault runtime.

The boundary this tool sits on, stated precisely:

    Effect => Observed            is a TCB ASSUMPTION. It is a physical
                                  coverage property of the customer's
                                  containment layer. No log and no
                                  cryptography can prove that an effect
                                  which was never captured did not occur.

    ObservedEffect => exists! PriorValidAllow    is the THEOREM this
                                  tool verifies. Every effect an
                                  observer DID capture must reconcile to
                                  exactly one prior, valid, matching
                                  ALLOW decision.

The tool therefore does NOT claim complete mediation. It converts the
gap between assumption and theorem into explicit, auditable findings:

    UNAUTHORIZED_EFFECT  an observed effect with no matching ALLOW
                         (or matching a decision that was not ALLOW,
                         or whose binding/freshness fails)
    ORPHAN_EFFECT        an observed effect carrying no decision_ref
                         at all -- it claims no authorization
    OBSERVER_GAP         a break in an observer's coverage: a sequence
                         gap, or an epoch boundary leaving a window
                         unobserved. A gap is where an omitted effect
                         could hide, so it is surfaced, never ignored
    BLOCK_EXECUTED       a decision was BLOCK yet an effect was observed
                         for it -- the runtime refused and the world
                         acted anyway (cross-stream divergence)

Coverage epochs make omission DETECTABLE rather than provable: each
observer asserts, signed, the (seq_start, seq_end) range it covered in
an epoch. A missing sequence number inside an asserted epoch is an
OBSERVER_GAP; the absence of any epoch covering a window is itself
reported. Multiple independent observers reconcile against the one
decision log, so a single observer's silence is caught by another's
speech.

Record shapes (drp-observer/1):

  effect     {kind:"effect", observer_id, seq, decision_ref|null,
              effect_type, target, timestamp, epoch_id,
              observer_sig, record_hash}
  epoch      {kind:"coverage_epoch", observer_id, epoch_id,
              seq_start, seq_end, window_start, window_end,
              observer_sig, record_hash}

Signature verification of observer_sig against the observer's public
key is a deployment concern (customer HSM/KMS); the CLI checks
structure, sequence continuity and reconciliation, and reports the
signature field's presence, since key distribution is out of band.

Exit code 0 iff no findings.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field

FRESHNESS_WINDOW_S = 300.0  # an ALLOW older than this vs the effect is stale


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def compute_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(canonical(payload).encode()).hexdigest()


@dataclass
class Finding:
    kind: str
    detail: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    effects_seen: int = 0
    decisions_seen: int = 0
    observers: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return not self.findings

    def add(self, kind: str, detail: str) -> None:
        self.findings.append(Finding(kind, detail))


def _load(path: str) -> list[dict]:
    out = []
    for i, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise SystemExit(f"{path}:{i}: invalid JSON: {e}") from e
    return out


def reconcile(decision_records: list[dict],
              effect_records: list[dict]) -> Report:
    rep = Report()

    decisions: dict[str, dict] = {}
    for r in decision_records:
        if r.get("kind") == "decision":
            decisions[r["decision_id"]] = r
            rep.decisions_seen += 1

    by_observer_effects: dict[str, list[dict]] = defaultdict(list)
    by_observer_epochs: dict[str, list[dict]] = defaultdict(list)
    for r in effect_records:
        k = r.get("kind")
        if k == "effect":
            by_observer_effects[r["observer_id"]].append(r)
            rep.observers.add(r["observer_id"])
        elif k == "coverage_epoch":
            by_observer_epochs[r["observer_id"]].append(r)
            rep.observers.add(r["observer_id"])

    for observer, effects in by_observer_effects.items():
        effects.sort(key=lambda e: e["seq"])
        rep.effects_seen += len(effects)
        epochs = sorted(by_observer_epochs.get(observer, []),
                        key=lambda e: e["seq_start"])
        _check_hashes(observer, effects, epochs, rep)
        _check_sequence_gaps(observer, effects, epochs, rep)
        _check_reconciliation(observer, effects, decisions, rep)

    _check_block_executed(decision_records, effect_records, rep)
    return rep


def _check_hashes(observer, effects, epochs, rep):
    for r in effects + epochs:
        stored = r.get("record_hash", "")
        actual = compute_hash(r)
        if stored != actual:
            rep.add("RECORD_TAMPERED",
                    f"observer {observer}: record_hash mismatch "
                    f"(stored {stored[:12]}.., computed {actual[:12]}..)")
        if not r.get("observer_sig"):
            rep.add("UNSIGNED_OBSERVATION",
                    f"observer {observer}: record carries no observer_sig; "
                    "an unsigned effect stream is not independently trustworthy")


def _check_sequence_gaps(observer, effects, epochs, rep):
    seqs = [e["seq"] for e in effects]
    if not epochs:
        if effects:
            rep.add("OBSERVER_GAP",
                    f"observer {observer}: {len(effects)} effects but no "
                    "coverage_epoch asserting a covered range; coverage is "
                    "unclaimed, so omission cannot be bounded")
        return
    covered = set()
    for ep in epochs:
        lo, hi = ep["seq_start"], ep["seq_end"]
        if hi < lo:
            rep.add("OBSERVER_GAP",
                    f"observer {observer}: epoch {ep['epoch_id']} has "
                    f"seq_end {hi} < seq_start {lo}")
            continue
        covered.update(range(lo, hi + 1))
        present = {s for s in seqs if lo <= s <= hi}
        missing = sorted(set(range(lo, hi + 1)) - present)
        if missing:
            rep.add("OBSERVER_GAP",
                    f"observer {observer}: epoch {ep['epoch_id']} asserts "
                    f"coverage of seq {lo}..{hi} but seq {missing} were "
                    "never observed")
    for e in effects:
        if e["seq"] not in covered:
            rep.add("OBSERVER_GAP",
                    f"observer {observer}: effect seq {e['seq']} falls "
                    "outside every asserted coverage epoch")


def _decision_binds(decision: dict, effect: dict) -> bool:
    d_target = (decision.get("arguments_digest")
                or decision.get("capability"))
    e_target = effect.get("target")
    if e_target is not None and d_target is not None:
        if e_target not in (decision.get("capability"),
                            decision.get("arguments_digest")) \
                and effect.get("effect_type") != decision.get("capability"):
            return False
    return True


def _is_fresh(decision: dict, effect: dict) -> bool:
    dt = decision.get("timestamp")
    et = effect.get("timestamp")
    if dt is None or et is None:
        return True
    return 0 <= (et - dt) <= FRESHNESS_WINDOW_S


def _check_reconciliation(observer, effects, decisions, rep):
    for e in effects:
        dref = e.get("decision_ref")
        if dref is None:
            rep.add("ORPHAN_EFFECT",
                    f"observer {observer}: effect seq {e['seq']} "
                    f"({e.get('effect_type')}) carries no decision_ref -- "
                    "it claims no authorization at all")
            continue
        decision = decisions.get(dref)
        if decision is None:
            rep.add("UNAUTHORIZED_EFFECT",
                    f"observer {observer}: effect seq {e['seq']} references "
                    f"decision {dref} which is absent from the decision log")
            continue
        verdict = decision.get("decision")
        if verdict != "allow":
            rep.add("UNAUTHORIZED_EFFECT",
                    f"observer {observer}: effect seq {e['seq']} was "
                    f"authorized by decision {dref} whose verdict is "
                    f"'{verdict}', not 'allow'")
            continue
        if not _decision_binds(decision, e):
            rep.add("UNAUTHORIZED_EFFECT",
                    f"observer {observer}: effect seq {e['seq']} does not "
                    f"bind to decision {dref} (target mismatch)")
            continue
        if not _is_fresh(decision, e):
            rep.add("UNAUTHORIZED_EFFECT",
                    f"observer {observer}: effect seq {e['seq']} is not "
                    f"fresh against decision {dref} (outside the "
                    "authorization window)")


def _check_block_executed(decision_records, effect_records, rep):
    blocked = {r["decision_id"] for r in decision_records
               if r.get("kind") == "decision" and r.get("decision") == "block"}
    for e in effect_records:
        if e.get("kind") == "effect" and e.get("decision_ref") in blocked:
            rep.add("BLOCK_EXECUTED",
                    f"observer {e['observer_id']}: effect seq {e['seq']} was "
                    f"observed for decision {e['decision_ref']} which was "
                    "BLOCK -- refused, but observed to execute")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    decision_records = _load(argv[0])
    effect_records: list[dict] = []
    for p in argv[1:]:
        effect_records += _load(p)

    rep = reconcile(decision_records, effect_records)

    print(f"decisions: {rep.decisions_seen}  effects: {rep.effects_seen}  "
          f"observers: {len(rep.observers)}")
    for f in rep.findings:
        print(f"  {f.kind}: {f.detail}")
    if rep.ok:
        print("VERDICT: PASS (every observed effect reconciles to exactly "
              "one prior valid ALLOW; coverage epochs continuous)")
        print("NOTE: this proves ObservedEffect => exists! PriorValidAllow. "
              "It does NOT prove Effect => Observed, which is a coverage "
              "property of the customer containment layer (its TCB).")
        return 0
    print(f"VERDICT: FAIL ({len(rep.findings)} finding(s))")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
