# Receiver kit quickstart

Run a PrivateVault receiver gate on your own machine, with your own key, and
watch it refuse an altered payment. About 15 minutes. Every command is run
from the repository root unless noted.

What you get at the end: a gate that admitted one permitted transfer, refused
the same transfer with the amount changed, refused a replay, and a receipt
chain signed by your key that passes the open verifier.

## 0. Prerequisites

- Docker with Compose v2
- Python 3.12
- This repository cloned

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

## 1. Generate your keys (they never leave this machine)

```sh
python -m network.receiver_kit.keygen receiver --out network/receiver_kit/keys
python -m network.receiver_kit.keygen issuer   --out network/receiver_kit/keys
```

Expected:

```
private key written to network/receiver_kit/keys/receiver.key (mode 0600, keep it here)
public key written to  network/receiver_kit/keys/receiver.pub
receiver public key: <BASE64>
private key written to network/receiver_kit/keys/issuer.key (mode 0600, keep it here)
public key written to  network/receiver_kit/keys/issuer.pub
issuer public key: <BASE64>
```

The receiver key is yours: it signs every receipt. The issuer key is a
throwaway that stands in for PrivateVault's permit signer so the demo runs
without any other party. The `keys/` directory is ignored by git.

## 2. Configure the gate

```sh
cd network/receiver_kit
cp .env.example .env
sed -i.bak "s#PASTE_ISSUER_PUBLIC_KEY_HERE#$(cat keys/issuer.pub)#" .env && rm .env.bak
mkdir -p data
```

`.env` now pins the issuer's public key. Nothing else needs changing for the
demo. `PV_RECEIVER_ID` is who you are; a permit that names another receiver
is refused.

About the destination: `PV_RECEIVER_DESTINATIONS=https://payments.partner.example`
is a logical identity the permit must name exactly, not an address. The demo
gate listens on plain `http://localhost:8080`; the permit still says `https`
because the gate admits only `https` permits.

## 3. Start the gate and the dummy upstream

```sh
docker compose up --build -d
docker compose logs gate | head -12
```

Expected in the gate log:

```
receiver gate
  receiver_id          payments.partner.example
  destinations         https://payments.partner.example
  issuer organisation  lender.example
  issuer key ids       ea-signer
  trust bundle digest  sha256:<64 hex>
  receipt key id       partner-receiver-01
  receipt public key   <BASE64, same as keys/receiver.pub>
  ledger               /data/receiver.db
  upstream             http://upstream:9001
  unprotected          GET /_health
```

How the key is handled: the gate container starts as root only to copy
`keys/receiver.key` into a private tmpfs owned by the gate user (uid 10001,
mode 0400), then drops root before the gate starts. The mounted file is
never modified. This is what makes the same compose file work on Linux,
where a bind-mounted 0600 file keeps your uid.

Demo only: port 9001 and `GET /_seen` on the upstream exist so the next step
can prove what never reached it. A real partner never exposes the upstream.
The gate is its only network path.

## 4. Send three requests from outside

```sh
cd ../..
python -m network.receiver_kit.send_test
```

Expected:

```
PASS  valid permit    got 200                              want 200                              upstream +1  upstream saw it once, permit header stripped, receipt returned
PASS  amount changed  got 403 RECEIVER_WIRE_MISMATCH       want 403 RECEIVER_WIRE_MISMATCH       upstream +0  upstream never saw the altered body
PASS  replay          got 409 RECEIVER_PERMIT_CONSUMED     want 409 RECEIVER_PERMIT_CONSUMED     upstream +0  permit already consumed; upstream saw nothing new
ALL PASS
```

What happened: `send_test` signed one permit for a 5,000 USD transfer with the
demo issuer key. The first request carried it and went through, once. The
second request carried the same permit with the body changed to 50,000 USD;
the gate recomputed the body digest, found it did not match the permit, and
refused before any byte reached the upstream. The third request was the first
one again; the receiver's own ledger had already consumed that permit.

Optional, the direct-call bypass:

```sh
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/api/v1/transfers \
  -H 'Content-Type: application/json' -d '{"amount":1}'
```

Expected: `403`. No permit, no entry.

## 5. Export the receipts and verify them with your key

The ledger lives in a Docker volume, so export inside the container and
copy the file out:

```sh
docker compose -f network/receiver_kit/docker-compose.yml exec gate \
  python -m network.receiver_kit.export_receipts --db /data/receiver.db --out /tmp/receipts.jsonl
docker compose -f network/receiver_kit/docker-compose.yml cp gate:/tmp/receipts.jsonl receipts.jsonl
python -I tools/verify_receiver_receipts.py --jsonl receipts.jsonl \
  --receiver-id payments.partner.example \
  --receiver-key "partner-receiver-01=$(cat network/receiver_kit/keys/receiver.pub)"
```

Expected (one more refused receipt if you ran the curl):

```
wrote 3 receipts to /tmp/receipts.jsonl
OK 3 receipts (1 admitted, 2 refused), mode=chain+signatures
```

The verifier is a standalone script. It does not import this package, and
the public key comes from your file, not from the receipts.

## 6. What you send back to us

Two files, nothing else:

- `receipts.jsonl`
- `network/receiver_kit/keys/receiver.pub`

Do not send `receiver.key`, `issuer.key`, `.env`, or the ledger database.
With the two files above, anyone can run the verifier and confirm that a gate
you operate, under a key only you hold, admitted the permitted action once
and refused the altered and replayed ones.

## 7. Stop

```sh
cd network/receiver_kit && docker compose down
```

## Settings reference

| Variable | Meaning |
|---|---|
| `PV_RECEIVER_ID` | Your receiver identity; must equal the permit's `credential_audience`. |
| `PV_RECEIVER_DESTINATIONS` | Logical destinations a permit may name, `;` separated. |
| `PV_ISSUER_ORGANISATION` | The issuing organisation named in permits. |
| `PV_ISSUER_KEYS` | `key_id=BASE64;...` permit-signing public keys you trust. |
| `PV_RECEIPT_KEY_FILE` | Path to your Ed25519 seed file (0600). Set by compose. Or `awskms:<key ARN>` / `gcpkms:<key version>` to keep the receipt key in your KMS (ADR 0023); check it first with `python tools/kms_smoke.py`. |
| `PV_RECEIPT_KEY_ID` | The id written into every receipt you sign. |
| `PV_UPSTREAM` | The system the gate forwards admitted requests to. Set by compose. |
| `PV_ALLOW_HTTP_UPSTREAM` | `1` only for a loopback upstream inside one host. |
| `PV_LEDGER_PATH` | SQLite file for the consume ledger and receipt chain. |
| `PV_UNPROTECTED_OPERATIONS` | `GET`/`HEAD` routes that bypass the gate, `;` separated. Writes cannot be unprotected. |
| `PV_GATE_UID`, `PV_GATE_GID` | Optional. The uid and gid the entrypoint drops to after copying the key (default 10001). |
| `PV_TRUST_BUNDLE_VERSION`, `PV_TRUST_BUNDLE_PINNED_AT` | Optional; both sides must agree. A pinned bundle file replaces these in Phase 2. |
| `PV_RECEIVER_TLS_CERT`, `PV_RECEIVER_TLS_KEY`, `PV_RECEIVER_CLIENT_CA` | Optional, all three or none: serve HTTPS and require a client certificate from that CA. Run `python -m network.receiver_kit.serve` (the default command serves plain HTTP). |
| `PV_RECEIVER_REQUIRE_PRESENTER` | `1` refuses permits that do not name a presenter (ADR 0022). Needs the three TLS variables. A permit that names one is always checked. |

## What this does not show

The pilot upstream is a stub that records requests. Coverage of a real API,
and making the gate its only network path, are deployment properties of your
system. Receipts prove what the gate admitted, not what the upstream did with
it. The ledger is a single SQLite file: one host.
