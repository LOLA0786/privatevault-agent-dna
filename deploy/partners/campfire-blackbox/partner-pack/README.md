# Campfire evaluation pack

Hosted PrivateVault interface for one sandbox write workflow. This zip is documentation and request samples. It is not the runtime and it does not include source.

You do not change your model stack. Do not use production credentials or customer data. The key you were given is scoped to `campfire-agent` and to `campfire.files.write_sandbox`.

The hosted evaluation must run with `PV_SECURE_PROFILE=1`. This zip does not enable that. `POST /v1/authorize` mints a signed permit. It does not dispatch a file and it does not prove live network delivery.

## 1. Set the host

```bash
export BASE_URL="https://YOUR-HOSTED-PRIVATEVAULT-URL"
export CAMPFIRE_API_KEY="the key delivered separately"
```

Confirm `GET /health` and `GET /ready` return 200.

## 2. Send the three examples

Replace `timestamp` in each JSON file with the current Unix time (seconds since epoch) before submission. The sample value is stale. The Postman collection uses `{{$timestamp}}` so it does this automatically.

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

## 3. Mint a permit after ALLOW

Do this only after a sealed ALLOW (`200` and `decision=allow`). Copy `record.decision_id` and `record.record_hash` from that response. `decision_receipt_digest` is `sha256:` plus the record hash. Copy `execution_action` from `examples/allow.json` as `action`. Do not send decide `dispatch_context` as `dispatch`. Authorize `dispatch` is the twelve fields below; decide uses six context fields.

```bash
python3 - <<'PY'
import hashlib, json, os, time, urllib.request

base = os.environ["BASE_URL"].rstrip("/")
key = os.environ["CAMPFIRE_API_KEY"]
allow = json.load(open("examples/allow.json"))
allow.pop("_timestamp_instruction", None)
allow["timestamp"] = time.time()

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("X-API-Key", key)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())

status, decided = call("POST", "/v1/decide", allow)
assert status == 200 and decided["decision"] == "allow", decided
record = decided["record"]
z = "sha256:" + ("0" * 64)
one = "sha256:" + ("1" * 64)
action = dict(allow["execution_action"])
dispatch = {
    "transport": "https",
    "destination": "sandbox.campfire.eval",
    "operation": "PUT /sandbox/notes.txt",
    "wire_content_type": "application/json",
    "serialization": "pv-json-parameters/0.1",
    "wire_content_encoding": "identity",
    "tool_id": "campfire.files.write_sandbox.v1",
    "tool_schema_digest": z,
    "tool_artifact_digest": one,
    "credential_audience": "sandbox.campfire.eval",
    "idempotency_key_digest": z,
    "retry_policy_digest": one,
}
wire = json.dumps(action["parameters"], allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
body = {
    "request_id": "campfire-auth-honest",
    "agent_id": "campfire-agent",
    "organisation_id": "campfire.eval",
    "decision_id": record["decision_id"],
    "action": action,
    "dispatch": dispatch,
    "expected_wire_bytes_digest": "sha256:" + hashlib.sha256(wire).hexdigest(),
    "expected_wire_bytes_length": len(wire),
    "expected_peer_identity_digest": one,
    "decision_receipt_digest": "sha256:" + record["record_hash"],
    "authority_receipt_digest": one,
    "approval_artifact_digest": z,
    "state_snapshot_digest": z,
    "policy_bundle_digest": one,
    "obligations_digest": z,
}
status, minted = call("POST", "/v1/authorize", body)
assert status == 200, minted
assert minted["authorization"]["signature"]
print("honest authorize 200")

path_body = json.loads(json.dumps(body))
path_body["request_id"] = "campfire-auth-path"
path_body["action"]["parameters"]["path"] = "/protected/secrets.txt"
status, path = call("POST", "/v1/authorize", path_body)
assert status == 403, path
assert path["detail"]["reason_code"] == "AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH"
print("changed path 403 AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH")

dest_body = json.loads(json.dumps(body))
dest_body["request_id"] = "campfire-auth-dest"
dest_body["dispatch"]["destination"] = "evil.example"
status, dest = call("POST", "/v1/authorize", dest_body)
assert status == 403, dest
assert dest["detail"]["reason_code"] == "AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH"
print("changed destination 403 AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH")
print("no file was dispatched")
PY
```

The wire digest and length must match the named JSON serialization of the action parameters. The peer digest remains an evaluation placeholder. They are not proof that bytes left the host. Replay and byte-mutation refusal remain the reference exact-byte test unless Campfire routes real tool execution through the PrivateVault dispatcher. Do not report `/v1/outcome` as `ok` unless the tool actually ran.

## 4. Evidence

Use the audit key (also delivered separately) on `GET /v1/verify` and `GET /v1/audit/export`. Detached envelopes are at `GET /v1/envelope/{record_hash}`. Verify with the public key you were given, not with a key from this zip.

## 5. Tell us

After the run, send:

* workflow tested
* setup friction
* unexpected verdicts
* missing fields
* whether you would integrate it

Full execution mediation requires Campfire's real tool path to call PrivateVault before the write, and to route mutation through the governed dispatcher. This pack does not do that for you. The service is single-instance. It does not claim horizontal scale, high-concurrency numbers, SOC 2, or ISO certification.
