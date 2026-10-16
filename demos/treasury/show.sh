#!/usr/bin/env bash
# One-terminal live show: services + dashboard + real Claude agent in the
# background, approver in the foreground. Ctrl+C stops everything.
#   demos/treasury/show.sh            live run (naive prompt, real Claude)
#   demos/treasury/show.sh policy     live run with the policy prompt
#   demos/treasury/show.sh saved      no API: dashboard on the last saved run
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
MODE="${1:-naive}"
LOG="$HERE/.run/agent-show.log"

# Stale PV_* from other demos break auth (401) - clear them for this shell.
for v in $(env | grep '^PV_' | cut -d= -f1); do unset "$v"; done
cd "$REPO"

open_url() { (command -v open >/dev/null && open "$1") || (command -v xdg-open >/dev/null && xdg-open "$1") || true; }

if [ "$MODE" = "saved" ]; then
  RUN="$(ls -t "$HERE"/runs/*.jsonl 2>/dev/null | head -1)"
  [ -n "$RUN" ] || { echo "no saved run in $HERE/runs"; exit 1; }
  echo "Showing saved run: $(basename "$RUN")"
  (sleep 1.5; open_url http://127.0.0.1:8765) &
  exec uv run python demos/treasury/dashboard.py --run "$RUN"
fi

PIDS=()
killtree() { for c in $(pgrep -P "$1" 2>/dev/null); do killtree "$c"; done; kill "$1" 2>/dev/null; }
cleanup() {
  echo; echo "Stopping..."
  for p in ${PIDS[@]+"${PIDS[@]}"}; do killtree "$p"; done
  make -s -C "$HERE" down >/dev/null 2>&1
  echo "Done. Agent log: $LOG"
}
trap cleanup EXIT INT TERM

echo "== 1/4 fresh services"
make -s -C "$HERE" down >/dev/null 2>&1
make -s -C "$HERE" up || { echo "services failed to start"; exit 1; }
mkdir -p "$HERE/.run"

echo "== 2/4 dashboard  http://127.0.0.1:8765"
uv run python demos/treasury/dashboard.py </dev/null >/dev/null 2>&1 &
PIDS+=($!)
sleep 1.5; open_url http://127.0.0.1:8765

echo "== 3/4 Claude agent ($MODE prompt) running in background; log: $LOG"
make -s -C "$HERE" "$MODE" </dev/null >"$LOG" 2>&1 &
PIDS+=($!)

echo "== 4/4 approver - type 'approve' or 'deny' when a request appears. Ctrl+C ends the show."
echo
make -s -C "$HERE" approve
