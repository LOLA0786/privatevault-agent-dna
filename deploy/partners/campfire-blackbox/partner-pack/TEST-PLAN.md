# Campfire test plan

One workflow: `campfire.files.write_sandbox`. Expected verdicts are deterministic policy, not drift scores.

Use `BASE_URL` and `CAMPFIRE_API_KEY` from the separately delivered secret. Do not put keys in this file.

## Health

`GET /health` and `GET /ready` should return 200 before you start.

## Scenario A: ALLOW

Replace `timestamp` in `examples/allow.json` with the current Unix time (seconds since epoch) before POST. The sample value is stale.

POST `examples/allow.json` to `/v1/decide`.

Expect HTTP 200, `decision=allow`, a sealed record with `protocol_version` `drp/0.2`. Digests on the record are computed by the server. Do not send `action_digest` or `dispatch_context_digest`.

Only then POST `/v1/authorize` bound to that `decision_id` and `record_hash`. Expect a signed permit with `max_uses=1`. Authorize does not perform the write.

## Scenario B: REVIEW

POST `examples/review.json`. Replace `timestamp` with the current Unix time first.

Expect HTTP 202, `decision=require_approval`. Do not execute. Authorize against this record must fail.

## Scenario C: BLOCK

POST `examples/block.json`. Replace `timestamp` with the current Unix time first.

Expect HTTP 403, `decision=block`. This 403 is the verdict. Do not retry. Do not execute. Authorize against this record must fail.

## Negative checks

These mint-time checks are executable against the hosted API:

* Audit key on `/v1/decide` is rejected.
* Changing `execution_action.parameters.path` after ALLOW refuses mint.
* Changing `dispatch.destination` after ALLOW refuses mint.
* Substituting another record's id or receipt refuses mint.

Replay of a consumed permit and refusal of mutated wire bytes are demonstrated by the reference exact-byte test. They are not a partner-executable live dispatch test unless Campfire routes its real tool execution through the PrivateVault dispatcher.

`POST /v1/outcome` with `status=ok` is false evidence unless the tool actually ran. If it did not dispatch, record `refused` or omit the outcome. `ok` plus `dispatched=false` is refused.

## Evidence

Export with `GET /v1/audit/export`. Chain verify with `GET /v1/verify`. Fetch `GET /v1/envelope/{record_hash}` and verify the detached signature with the independently delivered public key.

If an outcome is ever `indeterminate`, do not auto-retry.
