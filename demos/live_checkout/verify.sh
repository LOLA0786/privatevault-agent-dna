#!/usr/bin/env bash
# Independent verification of the gate's receipts, as the other party does it.
#
#   demos/live_checkout/verify.sh RECEIPTS.jsonl GATE_PUBLIC_KEY_FILE
#
# Needs: this script, tools/verify_receiver_receipts.py (the open verifier,
# standard library plus PyNaCl for signatures), the receipts, and the gate's
# published public key. No PrivateVault package, no API, no ledger.
#
# Runs the verifier on the receipts as given (expect OK), then flips one
# byte in a copy and runs it again (expect FAIL). Exit 0 only if both
# happened. Set PYTHON to choose an interpreter (default python3).
set -euo pipefail

RECEIPTS="${1:?receipts.jsonl}"
PUBKEY_FILE="${2:?gate public key file}"
RECEIVER_ID="${PV_RECEIVER_ID:-checkout.gateway.example}"
KEY_ID="${PV_RECEIPT_KEY_ID:-gateway-receiver-01}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="${VERIFIER:-$HERE/../../tools/verify_receiver_receipts.py}"
PY="${PYTHON:-python3}"

PUBKEY="$(tr -d '[:space:]' <"$PUBKEY_FILE")"

echo "== receipts as exported"
set +e
$PY -I "$VERIFIER" --jsonl "$RECEIPTS" --receiver-id "$RECEIVER_ID" --receiver-key "$KEY_ID=$PUBKEY"
first=$?
set -e

TAMPERED="$(mktemp -t receipts-tampered.XXXXXX)"
trap 'rm -f "$TAMPERED"' EXIT
# Flip one byte: change the first hex digit of the first wire_bytes_digest.
$PY -I - "$RECEIPTS" "$TAMPERED" <<'EOF'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
marker = b'"wire_bytes_digest": "sha256:'
i = data.find(marker)
if i < 0:
    sys.exit("no wire_bytes_digest found")
j = i + len(marker)
flipped = b"1" if data[j : j + 1] != b"1" else b"2"
open(dst, "wb").write(data[:j] + flipped + data[j + 1 :])
EOF

echo
echo "== one byte changed (copy at $TAMPERED)"
set +e
$PY -I "$VERIFIER" --jsonl "$TAMPERED" --receiver-id "$RECEIVER_ID" --receiver-key "$KEY_ID=$PUBKEY"
second=$?
set -e

echo
if [ "$first" -eq 0 ] && [ "$second" -ne 0 ]; then
  echo "VERIFY: OK as exported, FAIL after one byte changed. Receipts are what the gate signed."
  exit 0
fi
echo "VERIFY: unexpected result (exported=$first, tampered=$second)" >&2
exit 1
