# Campfire black-box deployment (internal)

Do not ship this file to Campfire. Do not copy it into the partner zip.

## What we host

We run the current PrivateVault runtime. Campfire calls it over HTTPS with a dedicated `campfire-agent` full-scope key. An audit-only key is optional for their verifier. Keys are delivered separately from the zip.

## Bootstrap

```bash
uv run python tools/init_campfire_blackbox.py --out /var/lib/privatevault/campfire
```

That directory is mode 0700. Plaintext keys and receipt seed live in `keys.secrets.txt` (0600). Execution and dispatch-witness private keys are 0600 files. The API-key registry stores hashes only.

Do not pass `--replace-existing` unless you intend to rotate. The tool will not silently rotate.

## Run

Authentication must be on. Never set `PV_ALLOW_NO_AUTH=1`.

Point the process at the generated files:

* `PV_API_KEYS_FILE`
* `PV_GRANTS_FILE`
* `PV_POLICY_FILE`
* `PV_EXECUTION_SIGNER_KEY`
* `PV_TRUST_BUNDLE`
* `PV_EXECUTION_TRUST_BUNDLE_FILE`
* `PV_DISPATCH_WITNESS_KEY`
* `PV_RECEIPT_SIGNING_KEY`
* `PV_TRUSTED_PUBLIC_KEYS`
* `PV_DB_PATH` on our disk, not theirs
* `PV_ORGANISATION_ID=campfire.eval`
* `PV_BASELINE_CAPABILITIES=campfire.files.write_sandbox` (so the
  sandbox write is on the synthetic baseline; without it, novelty
  drift would escalate ALLOW to review). Confirm the override on
  `GET /v1/runtime` under `composition.baseline_capabilities`
  (`override=true` and the capability list). Unset, the field is
  `override=false` and default grant-plus-drift behaviour is unchanged.

Enable `PV_SECURE_PROFILE=1` only after every required signing, trust, grants, and API-key input exists. If any of those is missing, startup must fail closed.

Terminate TLS at ingress before exposing the service. Apply rate limits and request-size limits at that ingress. Do not log API keys, complete sensitive payloads, or private signing material.

Do not publish a Docker image of this runtime as the partner artifact. The current Python image contains inspectable source.

## Access control

Revoke Campfire by removing their hash from the key registry and restarting, or by replacing the registry after `--replace-existing` (that also rotates every key; prefer a targeted hash delete when you only want to cut Campfire).

Stop the sandbox by stopping the process and unmounting or deleting `PV_DB_PATH` plus the runtime directory. Private keys never leave that directory.

## Honesty

A remotely hosted decision service does not prove complete mediation of Campfire's downstream tool execution. Their harness must be structurally unable to write on any status other than ALLOW, and mutation must go through the governed dispatcher. Replay/byte-mutation refusal is demonstrated by the reference exact-byte test and is not a partner-executable live dispatch test unless Campfire routes its real tool execution through the PrivateVault dispatcher. The recording-transport exact-byte demo is not proof of network delivery. Do not auto-retry `INDETERMINATE`. Do not record `/v1/outcome` as `ok` when the tool was not dispatched.
