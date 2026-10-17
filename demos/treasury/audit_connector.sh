#!/usr/bin/env bash
# PrivateVault Audit (read-only MCP connector) over the treasury demo's records.
#
#   demos/treasury/audit_connector.sh          local, no sign-in: http://127.0.0.1:8790/mcp
#                                              (Claude Code, MCP Inspector)
#   demos/treasury/audit_connector.sh tunnel   OAuth sign-in on a public https URL through a
#                                              Cloudflare quick tunnel; add <url>/mcp to Claude
#                                              as a custom connector (needs: brew install cloudflared)
#
# The connector reads the demo's PrivateVault (port 8712) with the demo's
# audit-scoped key. Only the connector is exposed through the tunnel; the
# PrivateVault API stays on localhost. Ctrl+C stops everything this started.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_DIR="${PV_TREASURY_RUN_DIR:-$HERE/.run}"
KEY_FILE="$RUN_DIR/agents/auditor.key"
PV_URL="http://127.0.0.1:${PV_TREASURY_PORT_PRIVATEVAULT:-8712}"
PORT="${PV_AUDIT_PORT:-8790}"
MODE="${1:-local}"

# Stale PV_* settings from other demos would change how the services start.
for v in $(env | grep '^PV_' | cut -d= -f1); do
  case "$v" in PV_TREASURY_*|PV_AUDIT_PORT) ;; *) unset "$v" ;; esac
done
cd "$REPO" || exit 1

echo "== treasury services (PrivateVault on $PV_URL)"
make -s -C "$HERE" up >/dev/null || { echo "could not start the treasury services"; exit 1; }
[ -s "$KEY_FILE" ] || { echo "no auditor key at $KEY_FILE"; exit 1; }

case "$MODE" in
  local)
    echo "== PrivateVault Audit (local, no sign-in): http://127.0.0.1:$PORT/mcp"
    echo "   Claude Code: claude mcp add --transport http pv-audit http://127.0.0.1:$PORT/mcp"
    PV_AUDIT_API_KEY="$(cat "$KEY_FILE")" exec uv run python -m agent_dna.audit_connector \
      --pv-url "$PV_URL" --port "$PORT"
    ;;
  tunnel)
    command -v cloudflared >/dev/null || { echo "cloudflared not found: brew install cloudflared"; exit 1; }
    LOG="$RUN_DIR/logs/tunnel.log"
    mkdir -p "$RUN_DIR/logs"
    cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$LOG" 2>&1 &
    TUNNEL=$!
    trap 'kill "$TUNNEL" 2>/dev/null' EXIT INT TERM
    URL=""
    for _ in $(seq 1 60); do
      URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" | head -1)"
      [ -n "$URL" ] && break
      sleep 0.5
    done
    [ -n "$URL" ] || { echo "tunnel did not come up; see $LOG"; exit 1; }
    if command -v pbcopy >/dev/null; then
      pbcopy <"$KEY_FILE"
      KEY_NOTE="the auditor key is on your clipboard"
    else
      KEY_NOTE="paste the key from $KEY_FILE"
    fi
    echo "== PrivateVault Audit with OAuth sign-in"
    echo "   In Claude: Settings > Connectors > Add custom connector"
    echo "   URL: $URL/mcp"
    echo "   On the PrivateVault sign-in page, $KEY_NOTE."
    uv run python -m agent_dna.audit_connector --pv-url "$PV_URL" --port "$PORT" --public-url "$URL"
    ;;
  *)
    echo "usage: $0 [local|tunnel]"; exit 2 ;;
esac
