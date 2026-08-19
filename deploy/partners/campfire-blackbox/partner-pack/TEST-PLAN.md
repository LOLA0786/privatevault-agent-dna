# Campfire test plan

One workflow: `campfire.files.write_sandbox`. Expected verdicts are deterministic policy, not drift scores.

Use `BASE_URL` and `CAMPFIRE_API_KEY` from the separately delivered secret. Do not put keys in this file.

## Health

`GET /health` and `GET /ready` should return 200 before you start.

## Scenario A: ALLOW

POST `examples/allow.json` to `/v1/decide`.

Expect HTTP 200, `decision=allow`, a sealed record with `protocol_version` `drp/0.2`. Digests on the record are computed by the server. Do not send `action_digest` or `dispatch_context_digest`.

Only then POST `/v1/authorize` bound to that `decision_id` and `record_hash`. Expect a signed permit with `max_uses=1`. Authorize does not perform the write.

## Scenario B: REVIEW

POST `examples/review.json`.

Expect HTTP 202, `decision=require_approval`. Do not execute. Authorize against this record must fail.

## Scenario C: BLOCK

POST `examples/block.json`.

Expect HTTP 403, `decision=block`. This 403 is the verdict. Do not retry. Do not execute. Authorize against this record must fail.

## Negative checks

* Audit key on `/v1/decide` is rejected.
* Changing `execution_action.parameters.path` after ALLOW refuses mint.
* Changing `dispatch.destination` after ALLOW refuses mint.
* Substituting another record's id or receipt refuses mint.
* Replaying a consumed permit refuses.

## Evidence

Export with `GET /v1/audit/export`. Chain verify with `GET /v1/verify`. Fetch `GET /v1/envelope/{record_hash}` and verify the detached signature with the independently delivered public key.

If an outcome is ever `indeterminate`, do not auto-retry.
