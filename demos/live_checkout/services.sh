#!/usr/bin/env bash
# Start, stop and inspect the four demo services as local processes.
#
#   demos/live_checkout/services.sh up        # merchant-site, privatevault, checkout-gate, checkout-api
#   demos/live_checkout/services.sh status
#   demos/live_checkout/services.sh logs      # tail all four logs
#   demos/live_checkout/services.sh down
#
# Logs go to $RUN_DIR/logs/<service>.log, pids to $RUN_DIR/pids/. The run
# directory is demos/live_checkout/.run unless PV_LIVE_RUN_DIR is set.
# Ports: PV_LIVE_PORT_MERCHANT, _PRIVATEVAULT, _GATE, _CHECKOUT (defaults
# 8701-8704). Run from anywhere; the script finds the repository root.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_DIR="${PV_LIVE_RUN_DIR:-$HERE/.run}"
PY="${PYTHON:-uv run python}"
HOST="${PV_LIVE_HOST:-127.0.0.1}"
P_MERCHANT="${PV_LIVE_PORT_MERCHANT:-8701}"
P_PV="${PV_LIVE_PORT_PRIVATEVAULT:-8702}"
P_GATE="${PV_LIVE_PORT_GATE:-8703}"
P_CHECKOUT="${PV_LIVE_PORT_CHECKOUT:-8704}"
SERVICES=(merchant_site privatevault gate checkout_api)

port_of() {
  case "$1" in
    merchant_site) echo "$P_MERCHANT" ;;
    privatevault) echo "$P_PV" ;;
    gate) echo "$P_GATE" ;;
    checkout_api) echo "$P_CHECKOUT" ;;
  esac
}

health_of() {
  case "$1" in
    merchant_site) echo "http://$HOST:$P_MERCHANT/_health" ;;
    privatevault) echo "http://$HOST:$P_PV/ready" ;;
    gate) echo "http://$HOST:$P_GATE/_health" ;;
    checkout_api) echo "http://$HOST:$P_CHECKOUT/_health" ;;
  esac
}

alive() { [ -f "$RUN_DIR/pids/$1.pid" ] && kill -0 "$(cat "$RUN_DIR/pids/$1.pid")" 2>/dev/null; }

up() {
  if [ ! -f "$RUN_DIR/READY" ]; then
    (cd "$REPO" && $PY demos/live_checkout/bootstrap.py --run-dir "$RUN_DIR")
  fi
  mkdir -p "$RUN_DIR/logs" "$RUN_DIR/pids"
  # The gate must reach the checkout API on the port chosen here.
  export PV_LIVE_RUN_DIR="$RUN_DIR"
  export PV_UPSTREAM="http://$HOST:$P_CHECKOUT"
  for svc in "${SERVICES[@]}"; do
    if alive "$svc"; then
      echo "$svc already running (pid $(cat "$RUN_DIR/pids/$svc.pid"))"
      continue
    fi
    (
      cd "$REPO"
      nohup $PY -m "demos.live_checkout.services.$svc" --host "$HOST" --port "$(port_of "$svc")" \
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

logs() {
  tail -n "${1:-40}" -F "$RUN_DIR"/logs/*.log
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  logs) logs "${2:-40}" ;;
  *) echo "usage: $0 {up|down|status|logs [lines]}" >&2; exit 2 ;;
esac
