"""
AMLSim benchmark — real transaction data through the composed line.

HONESTY RULE, ENFORCED IN CODE: IS_FRAUD, ALERT_ID, ALERT_TYPE are
NEVER read into evidence. They are held out and used ONLY after
decide() returns, to score the verdict against ground truth. Any
future edit to this file that passes those fields into `evidence`
invalidates every number this script produces.

Sample size is capped (see SAMPLE_SIZE) for a fast, honest first
pass -- this is explicitly NOT the full 1.1M-row run, and the output
says so.
"""

import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.economics import CostAnomalyChecker
from agent_dna.grants import GrantRegistry
from agent_dna.trace import AgentAction
from agent_dna.uaal_layer import UAALConstraintChecker

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "amlsim"
SAMPLE_SIZE = 5000   # first honest pass -- raise once this is proven out


class NoOpScorer:
    """No behavioral profile trained on AMLSim yet -- drift stays
    silent for this first pass so results isolate the deterministic
    layers (L0/L1/L2/L3), which is what's actually being tested here."""
    def score(self, action, prev_capability=None):
        from agent_dna.advisory import AdvisorySignal, Severity
        return AdvisorySignal(
            agent_id=action.agent_id, capability=action.capability,
            drift_score=0.0, severity=Severity.INFO, reasons=[],
        )


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass
        r = R()
        r.violated = False
        r.message = ""
        return r


def load_accounts():
    accounts = {}
    with open(DATA_DIR / "accounts.csv") as f:
        for row in csv.DictReader(f):
            accounts[row["ACCOUNT_ID"]] = row
    return accounts


def load_transaction_sample(n):
    """First n TRANSFER rows. Ground truth (IS_FRAUD, ALERT_ID) is
    read here but stored SEPARATELY from what gets built into
    evidence below -- see build_evidence()."""
    rows = []
    with open(DATA_DIR / "transactions.csv") as f:
        for row in csv.DictReader(f):
            if row["TX_TYPE"] != "TRANSFER":
                continue
            rows.append(row)
            if len(rows) >= n:
                break
    return rows


def build_evidence(row, accounts, sender_history):
    """Evidence a real pre-execution system would legitimately have.
    Does NOT read row['IS_FRAUD'] or row['ALERT_ID'] -- ground truth
    is withheld from the engine entirely."""
    sender = accounts.get(row["SENDER_ACCOUNT_ID"], {})
    receiver = accounts.get(row["RECEIVER_ACCOUNT_ID"], {})
    amount = float(row["TX_AMOUNT"])

    hist = sender_history[row["SENDER_ACCOUNT_ID"]]
    avg_amount = (sum(hist) / len(hist)) if hist else amount

    return {
        "economics": {
            "estimated_cost_usd": amount,
            "historical_avg_cost_usd": max(avg_amount, 0.01),
        },
        "enterprise_state": {
            "sender_country": sender.get("COUNTRY", "unknown"),
            "receiver_country": receiver.get("COUNTRY", "unknown"),
            "cross_border": sender.get("COUNTRY") != receiver.get("COUNTRY"),
        },
    }


def main():
    print(f"Loading accounts + first {SAMPLE_SIZE} TRANSFER rows...")
    accounts = load_accounts()
    rows = load_transaction_sample(SAMPLE_SIZE)
    print(f"Loaded {len(rows)} transactions, {len(accounts)} accounts.\n")

    engine = DecisionEngine(
        scorer=NoOpScorer(),
        invariants=Invariants(),
        authorizer=GrantRegistry(),   # empty on purpose: nothing pre-granted,
                                        # matches "unknown agent, no standing trust"
        uaal=UAALConstraintChecker(),
        economics=CostAnomalyChecker(),
    )

    sender_history = defaultdict(list)
    confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    verdict_counts = defaultdict(int)

    start = time.perf_counter()
    for row in rows:
        # ground truth -- held out, used ONLY below, after decide()
        is_fraud_ground_truth = row["IS_FRAUD"].strip().lower() == "true"

        action = AgentAction(
            agent_id=row["SENDER_ACCOUNT_ID"],
            capability="payment.transfer",
            timestamp=float(row["TIMESTAMP"]),
            arguments={
                "amount": float(row["TX_AMOUNT"]),
                "target": row["RECEIVER_ACCOUNT_ID"],
            },
        )
        evidence = build_evidence(row, accounts, sender_history)

        result = engine.decide(action, evidence=evidence)
        verdict_counts[result.decision.value] += 1

        flagged = result.decision != Decision.ALLOW  # BLOCK or REQUIRE_APPROVAL

        if flagged and is_fraud_ground_truth:
            confusion["tp"] += 1
        elif flagged and not is_fraud_ground_truth:
            confusion["fp"] += 1
        elif not flagged and is_fraud_ground_truth:
            confusion["fn"] += 1
        else:
            confusion["tn"] += 1

        sender_history[row["SENDER_ACCOUNT_ID"]].append(float(row["TX_AMOUNT"]))

    elapsed = time.perf_counter() - start

    print("=" * 60)
    print(f"AMLSim sample run -- {len(rows)} real transactions")
    print("(FIRST PASS -- capped sample, deterministic layers only,")
    print(" no behavioral profile trained on this data yet)")
    print("=" * 60)
    print(f"elapsed          : {elapsed:.2f}s  ({len(rows)/elapsed:.0f} decisions/sec)")
    print()
    print("verdict distribution:")
    for v, c in sorted(verdict_counts.items()):
        print(f"  {v:<18}: {c}")
    print()

    tp, fp, tn, fn = confusion["tp"], confusion["fp"], confusion["tn"], confusion["fn"]
    total_fraud = tp + fn
    total_clean = tn + fp
    recall = tp / total_fraud if total_fraud else float("nan")
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    fpr = fp / total_clean if total_clean else float("nan")

    print(f"ground truth      : {total_fraud} labeled fraud, {total_clean} labeled clean")
    print(f"flagged & fraud   : {tp}  (true positive)")
    print(f"flagged & clean   : {fp}  (false positive)")
    print(f"unflagged & fraud : {fn}  (false negative -- MISSED)")
    print(f"unflagged & clean : {tn}  (true negative)")
    print()
    print(f"recall (of labeled fraud, % flagged)      : {recall:.1%}" if total_fraud else "recall: n/a (no fraud in sample)")
    print(f"precision (of flagged, % actually fraud)  : {precision:.1%}" if (tp+fp) else "precision: n/a (nothing flagged)")
    print(f"false positive rate (of clean, % flagged) : {fpr:.1%}" if total_clean else "fpr: n/a")
    print()
    print("HONESTY NOTE: 'flagged' means BLOCK or REQUIRE_APPROVAL --")
    print("this engine is a policy/behavior enforcement layer, not a")
    print("purpose-built fraud classifier. This number shows what the")
    print("deterministic layers catch using only legitimate")
    print("pre-execution evidence (amount-vs-history, cross-border),")
    print("with NO behavioral training and NO fraud-specific tuning.")
    print("A production deployment would train L4 on this account's")
    print("real history and likely improve both numbers materially.")


if __name__ == "__main__":
    main()
