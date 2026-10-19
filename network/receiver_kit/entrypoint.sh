#!/bin/sh
# Receiver kit entrypoint.
#
# The container starts as root for one purpose. A key file bind-mounted from
# the host keeps the host's uid on Linux, so a fixed non-root gate user could
# not read a 0600 file (Docker Desktop on macOS remaps ownership and hides
# this). Root copies the key into a private tmpfs owned by the gate user with
# mode 0400, then drops to that user with no capabilities and no new
# privileges, and execs the command. The mounted original is never modified.
# The same applies to the TLS server key and the revocation-list API key.
#
# Started as a non-root user (for example via a `user:` override), nothing is
# copied and the key must already be readable by that user only.
set -eu

RUN_UID="${PV_GATE_UID:-10001}"
RUN_GID="${PV_GATE_GID:-10001}"
PRIVATE_DIR=/run/pv

if [ "$(id -u)" != "0" ]; then
  exec "$@"
fi

# Hand one secret file to the gate user: copy it into the private tmpfs with
# mode 0400 and point the variable at the copy. Unset variables are skipped.
hand_over() {
  var="$1"; name="$2"
  eval "src=\${$var:-}"
  [ -n "$src" ] || return 0
  if [ ! -r "$src" ]; then
    echo "entrypoint: $var=$src is not readable" >&2
    exit 1
  fi
  install -d -m 0700 -o "$RUN_UID" -g "$RUN_GID" "$PRIVATE_DIR"
  install -m 0400 -o "$RUN_UID" -g "$RUN_GID" "$src" "$PRIVATE_DIR/$name"
  export "$var=$PRIVATE_DIR/$name"
}

# A KMS reference (awskms:..., gcpkms:...) is not a file: nothing to copy.
case "${PV_RECEIPT_KEY_FILE:-}" in
  awskms:*|gcpkms:*) ;;
  *) hand_over PV_RECEIPT_KEY_FILE receiver.key ;;
esac
# The TLS server key and the API key that fetches the revocation list.
hand_over PV_RECEIVER_TLS_KEY tls.key
hand_over PV_REVOCATION_API_KEY_FILE revocation-api.key

# The ledger volume is created by Docker; make sure the gate user owns it.
if [ -d /data ]; then
  chown "$RUN_UID:$RUN_GID" /data
fi

exec setpriv --reuid "$RUN_UID" --regid "$RUN_GID" --clear-groups \
  --inh-caps=-all --no-new-privs "$@"
