#!/usr/bin/env bash
# Four panes: agent | privatevault | gate | checkout-api, plus a second
# window for the human approver and one for the merchant site.
#
#   demos/live_checkout/tmux.sh            # start services, open the layout
#   tmux attach -t pv-live                 # if detached
#
# The agent pane is a shell with the command ready to run so you can start
# it when the call is ready. Needs tmux and the services started by
# services.sh (this script starts them if they are not running).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_DIR="${PV_LIVE_RUN_DIR:-$HERE/.run}"
SESSION="${PV_LIVE_TMUX_SESSION:-pv-live}"

command -v tmux >/dev/null || { echo "tmux is not installed (brew install tmux)"; exit 2; }
"$HERE/services.sh" up
export PV_LIVE_RUN_DIR="$RUN_DIR"

tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n demo -x 220 -y 60 -c "$REPO"
# left: agent shell; right column: three service logs
tmux send-keys -t "$SESSION:demo" "clear; echo 'agent pane. run:'; echo '  uv run python demos/live_checkout/agent.py'; echo '  uv run python demos/live_checkout/agent.py --compromised-tool --bypass-sidecar'" C-m
tmux split-window -h -t "$SESSION:demo" -c "$REPO" "tail -n 30 -F '$RUN_DIR/logs/privatevault.log'"
tmux split-window -v -t "$SESSION:demo.1" -c "$REPO" "tail -n 30 -F '$RUN_DIR/logs/gate.log'"
tmux split-window -v -t "$SESSION:demo.2" -c "$REPO" "tail -n 30 -F '$RUN_DIR/logs/checkout_api.log'"
tmux select-layout -t "$SESSION:demo" main-vertical
tmux select-pane -t "$SESSION:demo.0"

tmux new-window -t "$SESSION" -n approver -c "$REPO" "uv run python demos/live_checkout/approve.py --run-dir '$RUN_DIR'"
tmux new-window -t "$SESSION" -n merchant -c "$REPO" "tail -n 30 -F '$RUN_DIR/logs/merchant_site.log'"
tmux select-window -t "$SESSION:demo"
tmux attach -t "$SESSION"
