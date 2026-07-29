#!/usr/bin/env bash
# Pre-flight for the MS RiskTec demo. Runs every step in presentation
# order, times it, and fails loudly. Run this before you screen-share,
# not during.
set -u

PY="${PY:-python3}"
PASS=0
FAIL=0
STEPS=()

banner() { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "$(printf '=%.0s' {1..64})"; }

check() {
  local name="$1"; shift
  local start end rc out
  start=$(date +%s)
  out=$("$@" 2>&1); rc=$?
  end=$(date +%s)
  local secs=$((end - start))
  if [ $rc -eq "${EXPECT:-0}" ]; then
    printf '  \033[32mPASS\033[0m  %-46s %2ds\n' "$name" "$secs"
    PASS=$((PASS + 1))
  else
    printf '  \033[31mFAIL\033[0m  %-46s %2ds  (exit %d)\n' "$name" "$secs" "$rc"
    echo "$out" | tail -6 | sed 's/^/        /'
    FAIL=$((FAIL + 1))
    STEPS+=("$name")
  fi
}

banner "0. ENVIRONMENT"
$PY --version
echo "  repo: $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"
echo "  dirty: $(git status --porcelain 2>/dev/null | wc -l) uncommitted file(s)"

banner "1. BLAST RADIUS  (open with this)"
check "authority_blast_radius_demo" $PY examples/authority_blast_radius_demo.py

banner "2. AUTHORITY DERIVATION  (the Balaji answer)"
check "authority_derivation_demo" $PY examples/authority_derivation_demo.py

banner "3. FULL STACK ACCEPTANCE"
check "executive_acceptance_demo" $PY examples/executive_acceptance_demo.py

banner "4. PV SCAN  (part one of the write-up)"
cat > /tmp/demo-bfsi.jsonl <<'EOF'
{"agent_id":"refund-agent","tool":"case.read","timestamp":"2026-07-29T09:00:00Z","arguments":{"case_id":"RF-1042"}}
{"agent_id":"refund-agent","tool":"refund.recommend","timestamp":"2026-07-29T09:00:05Z","arguments":{"amount":400000}}
{"agent_id":"refund-agent","tool":"refund.issue","timestamp":"2026-07-29T09:00:09Z","arguments":{"amount":400000}}
{"agent_id":"payments-agent","tool":"payment.execute","timestamp":"2026-07-29T09:10:00Z","arguments":{"amount":5000000}}
{"agent_id":"payments-agent","tool":"ledger.update","timestamp":"2026-07-29T09:10:04Z","arguments":{}}
{"agent_id":"ops-agent","tool":"customer.export","timestamp":"2026-07-29T09:20:00Z","arguments":{"rows":48000}}
{"agent_id":"ops-agent","tool":"account.list","timestamp":"2026-07-29T09:21:00Z","arguments":{}}
EOF
check "pvscan on BFSI log" $PY tools/pvscan.py /tmp/demo-bfsi.jsonl
check "pvscan JSON output" $PY tools/pvscan.py /tmp/demo-bfsi.jsonl --json /tmp/demo-scan.json

banner "5. INDEPENDENT VERIFIER  (close with this)"
check "verify clean vectors" $PY tools/verify_records.py spec/test-vectors/clean.jsonl
EXPECT=1 check "detect tampered field" $PY tools/verify_records.py spec/test-vectors/tampered_field.jsonl
EXPECT=1 check "detect deleted record" $PY tools/verify_records.py spec/test-vectors/deleted_record.jsonl

banner "6. VERIFIER INDEPENDENCE"
# AST, not grep: verify_records.py has a docstring line that begins
# "import agent_dna", and a text match reports a forgery that is not there.
INDEP=$($PY - <<'PYCHK'
import ast
LOCAL = {"agent_dna", "privatevault"}
def roots(path):
    out = set()
    for n in ast.walk(ast.parse(open(path).read())):
        if isinstance(n, ast.Import):
            out |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            out.add(n.module.split(".")[0])
    return out
v = roots("tools/verify_records.py") & LOCAL
c = roots("tools/pv_authority_cli.py") & LOCAL
print("CLEAN" if not v else "LEAKED:" + ",".join(sorted(v)))
print("WRAPS" if c else "STANDALONE")
PYCHK
)
if [ "$(echo "$INDEP" | head -1)" = "CLEAN" ]; then
  printf '  \033[32mPASS\033[0m  verify_records.py imports nothing from this repo\n'
  PASS=$((PASS + 1))
else
  printf '  \033[31mFAIL\033[0m  %s\n' "$(echo "$INDEP" | head -1)"
  FAIL=$((FAIL + 1))
fi
if [ "$(echo "$INDEP" | tail -1)" = "WRAPS" ]; then
  printf '  \033[33mNOTE\033[0m  pv_authority_cli wraps the runtime -- say so out loud\n'
fi

banner "RESULT"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ $FAIL -gt 0 ]; then
  printf '\n  Broken before you present:\n'
  for s in "${STEPS[@]}"; do printf '    - %s\n' "$s"; done
  exit 1
fi
printf '\n  Every demo step runs. Record it now as a fallback.\n'
