# Campfire evaluation pack

Hosted PrivateVault interface for one sandbox write workflow. This zip is documentation and request samples. It is not the runtime and it does not include source.

You do not change your model stack. Do not use production credentials or customer data. The key you were given is scoped to `campfire-agent` and to `campfire.files.write_sandbox`.

## 1. Set the host

```bash
export BASE_URL="https://YOUR-HOSTED-PRIVATEVAULT-URL"
export CAMPFIRE_API_KEY="the key delivered separately"
```

## 2. Send the three examples

`200` is ALLOW. `202` is REQUIRE_APPROVAL: do not execute. `403` is BLOCK: do not execute. Any other status is also non-executable. Do not treat `403` as a retryable HTTP error.

```bash
curl -sS -D - "$BASE_URL/v1/decide" \
  -H "X-API-Key: $CAMPFIRE_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @examples/allow.json

curl -sS -D - "$BASE_URL/v1/decide" \
  -H "X-API-Key: $CAMPFIRE_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @examples/review.json

curl -sS -D - "$BASE_URL/v1/decide" \
  -H "X-API-Key: $CAMPFIRE_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @examples/block.json
```

Mint a permit only after a sealed ALLOW (`200` and `decision=allow`). `POST /v1/authorize` signs a single-use permit. It does not dispatch the write.

## 3. Evidence

Use the audit key (also delivered separately) on `GET /v1/verify` and `GET /v1/audit/export`. Detached envelopes are at `GET /v1/envelope/{record_hash}`. Verify with the public key you were given, not with a key from this zip.

## 4. Tell us

After the run, send:

* workflow tested
* setup friction
* unexpected verdicts
* missing fields
* whether you would integrate it

Full execution mediation requires Campfire's real tool path to call PrivateVault before the write, and to route mutation through the governed dispatcher. This pack does not do that for you. The service is single-instance. It does not claim horizontal scale, high-concurrency numbers, SOC 2, or ISO certification.
