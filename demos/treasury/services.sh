#!/usr/bin/env bash
# Start, stop and inspect the three treasury demo services as local processes.
#
#   demos/treasury/services.sh up        # privatevault, gate, bank-api
#   demos/treasury/services.sh status
#   demos/treasury/services.sh logs
#   demos/treasury/services.sh down
#
# Logs go to $RUN_DIR/logs/<service>.log, pids to $RUN_DIR/pids/. The run
# directory is demos/treasury/.run unless PV_TREASURY_RUN_DIR is set.
# Ports: PV_TREASURY_PORT_PRIVATEVAULT, _GATE, _BANK (defaults 8712-8714).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_DIR="${PV_TREASURY_RUN_DIR:-$HERE/.run}"
PY="${PYTHON:-uv run python}"
HOST="${PV_TREASURY_HOST:-127.0.0.1}"
P_PV="${PV_TREASURY_PORT_PRIVATEVAULT:-8712}"
P_GATE="${PV_TREASURY_PORT_GATE:-8713}"
P_BANK="${PV_TREASURY_PORT_BANK:-8714}"
SERVICES=(privatevault gate bank_api)

port_of() {
  case "$1" in
    privatevault) echo "$P_PV" ;;
    gate) echo "$P_GATE" ;;
    bank_api) echo "$P_BANK" ;;
  esac
}

health_of() {
  case "$1" in
    privatevault) echo "http://$HOST:$P_PV/ready" ;;
    gate) echo "http://$HOST:$P_GATE/_health" ;;
    bank_api) echo "http://$HOST:$P_BANK/_health" ;;
  esac
}

alive() { [ -f "$RUN_DIR/pids/$1.pid" ] && kill -0 "$(cat "$RUN_DIR/pids/$1.pid")" 2>/dev/null; }

up() {
  if [ ! -f "$RUN_DIR/READY" ]; then
    (cd "$REPO" && $PY demos/treasury/bootstrap.py --run-dir "$RUN_DIR")
  fi
  mkdir -p "$RUN_DIR/logs" "$RUN_DIR/pids"
  export PV_TREASURY_RUN_DIR="$RUN_DIR"
  export PV_UPSTREAM="http://$HOST:$P_BANK"
  for svc in "${SERVICES[@]}"; do
    if alive "$svc"; then
      echo "$svc already running (pid $(cat "$RUN_DIR/pids/$svc.pid"))"
      continue
    fi
    (
      cd "$REPO"
      nohup $PY -m "demos.treasury.services.$svc" --host "$HOST" --port "$(port_of "$svc")" \
        >"$RUN_DIR/logs/$svc.log" 2>&1 &
      echo $! >"$RUN_DIR/pids/$svc.pid"
    )
    echo "started $svc on $HOST:$(port_of "$svc") (log $RUN_DIR/logs/$svc.log)"
  done
  for svc in "${SERVICES[@]}"; do
    url="$(health_of "$svc")"
    for _ in $(seq 1 60); do
      if curl -fsS -o /dev/null "$url" 2>/dev/null; then break; fi
      sleep 0.5
    done
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      echo "ready   $svc  $url"
    else
      echo "NOT READY $svc  $url  (see $RUN_DIR/logs/$svc.log)" >&2
      exit 1
    fi
  done
}

down() {
  for svc in "${SERVICES[@]}"; do
    if alive "$svc"; then
      kill "$(cat "$RUN_DIR/pids/$svc.pid")" 2>/dev/null || true
      echo "stopped $svc"
    fi
    rm -f "$RUN_DIR/pids/$svc.pid"
  done
}

status() {
  for svc in "${SERVICES[@]}"; do
    if alive "$svc"; then echo "running  $svc  :$(port_of "$svc")"; else echo "stopped  $svc"; fi
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  logs) tail -n "${2:-40}" -F "$RUN_DIR"/logs/*.log ;;
  *) echo "usage: $0 {up|down|status|logs [lines]}" >&2; exit 2 ;;
esac
