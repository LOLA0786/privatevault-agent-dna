# Changelog

Claims discipline applies here too: every entry corresponds to code
and a named test that runs in CI.

## Unreleased

### The receiver kit is hardened by default (ADR 0027, review finding 4)
- The gate serves mutual TLS only; `PV_RECEIVER_ALLOW_PLAINTEXT=1` is the
  explicit demo opt-out. The image runs `serve.py`; `app.py` (uvicorn)
  refuses TLS settings it cannot honour.
- With mTLS, presenter-bound permits are required unless
  `PV_RECEIVER_REQUIRE_PRESENTER=0`.
- `build_gate` attaches the signed revocation list. `revocations.py`
  refreshes it from `PV_REVOCATION_URL` with `PV_REVOCATION_API_KEY_FILE`;
  the gate refuses every permit (503) until a verified list is installed
  and after it expires. Required unless `PV_RECEIVER_ALLOW_NO_REVOCATION=1`.
- The entrypoint hands the TLS key and the revocation API key to the gate
  user like the receipt key. QUICKSTART gains "Run it for real"; the demo
  compose file sets both demo flags under "LOCAL DEMO ONLY".
- `tests/network/test_receiver_hardened.py`.

### The evidence a permit cites is the server's (ADR 0026, review finding 3)
- Decide seals the permit evidence in the server-only control-posture item:
  the policy bundle digest (policy file or OPA endpoint, grants file,
  operations registry; reported by `/v1/runtime`) and the grant the engine
  used. State snapshot and obligations are the all-zero digest: the API
  evaluates neither.
- `PV_PERMIT_EVIDENCE=server`, the default under `PV_SECURE_PROFILE`:
  `/v1/authorize` signs the sealed values. A caller value that differs is
  refused (`AUTHORIZE_EVIDENCE_MISMATCH`), a changed policy, grants or
  operations configuration since decide refuses the mint
  (`AUTHORIZE_POLICY_CHANGED`), and a record with no sealed evidence
  refuses (`AUTHORIZE_EVIDENCE_UNKNOWN`). `caller` is refused at start-up
  with the secure profile.
- `caller` (the default otherwise) signs caller values as given and fills
  omitted ones from the record; the response lists `caller_asserted`.
- The four request fields are optional. The agent gate and the partner pack
  no longer send them and read the signed values from the permit.
- The review's probe (arbitrary digests signed unchanged) is a regression
  test (`tests/test_permit_evidence.py`).

### A capability covers only its declared operations (ADR 0025, review finding 1)
- `PV_OPERATIONS_FILE` (`pv-operations/0.1`): per capability, the
  transport, destination, `METHOD path`, credential audience, resource and
  a JSON Schema for the parameters it may use. Malformed files stop
  start-up; `/v1/runtime` reports the registry digest.
- A bound decide its capability does not declare is a sealed BLOCK
  (`triggered_by: operation_registry`) before the ladder, so it spends no
  budget and consumes no approval. `/v1/authorize` checks again, including
  the credential audience, and names the operation and registry digest.
- Under `PV_SECURE_PROFILE`, minting without the file is refused
  (`AUTHORIZE_OPERATIONS_REQUIRED`); `init_secure_profile` writes an empty
  one, so nothing mints until operations are declared. Helm:
  `config.operationsKey`.
- The review's probe (read grant, transfer permit admitted) and its
  acceptance list are regression tests (`tests/test_operation_registry.py`).

### A permit never outlives its authority (ADR 0024, review finding 2)
- `/v1/authorize` refuses once the authority behind an ALLOW has ended:
  the verified approval's expiry, the grant's expiry, or the decision's
  mint window (`PV_DECISION_MINT_WINDOW_SECONDS`, default 300, measured
  from the record's sealed server timestamp). The permit's `expires_at` is
  capped at the earliest of these, so the sidecar and receiver enforce the
  same end. Refusals: `AUTHORIZE_AUTHORITY_EXPIRED`, and
  `AUTHORIZE_AUTHORITY_UNKNOWN` when the end cannot be established.
- The approval's verified expiry is stored with its single-use claim
  (`approval_consume.not_after`, SQLite and PostgreSQL, migrated in place).
  Approvals claimed before this change cannot mint; decide again.
- The review's four probes are inverted as regression tests, with
  restart, migration, concurrency, PostgreSQL and receiver checks
  (`tests/test_authority_freshness.py`).

### Claims corrected after the external review (19 October 2026)
- `WHAT-WE-DO-NOT-CLAIM.md`: removed three statements the code had
  outgrown (no per-decision mint limit, non-durable grant spend,
  envelopes lost on restart) and added the review's open findings:
  authority freshness at mint, capability-to-operation binding,
  caller-asserted permit digests, the receiver kit's default deployment,
  and full-ledger reads.
- `PRODUCTION-HARDENING.md`, `ROADMAP.md`, `findings/PHASE1-FOLLOW-UPS.md`:
  statuses brought up to date (PostgreSQL, backups, KMS, Helm,
  multi-instance correctness shipped; cross-host performance unmeasured)
  and the fix order for the review's findings.
- Every file and test cited by the claim pages must now exist
  (`test_claim_pages_cite_real_files_and_tests`).

### Structured documentation
- `docs/README.md`: index of every document by role and section, each
  marked current, reference, historical or experimental.
- `docs/architecture/`: overview, repository map, flows (sequence diagrams
  for decide, approval, authorize, dispatch, receiver gate, outcome,
  revocation, gateway, audit connector, verification, backup, and every
  HTTP route), data (every ledger table with writers and readers), trust
  and keys, deployment.
- `tools/depmap.py` generates `docs/architecture/DEPENDENCIES.md`: who
  depends on whom, module by module, in six layers, with every import that
  points up a layer listed.
- `tests/test_docs_structure.py`: code references and links resolve; every
  route, table, top-level directory and document is covered; the
  dependency page is fresh; no build output is tracked. Each check has a
  negative control.

### Helm chart (production readiness, phase 1 step 6a)
- `deploy/helm/privatevault`: the API as two replicas on PostgreSQL with
  the secure profile; non-root, read-only root filesystem, all
  capabilities dropped, RuntimeDefault seccomp, probes on `/health` and
  `/ready`, PodDisruptionBudget, optional HPA, NetworkPolicy, topology
  spread, IRSA/Workload Identity annotations for KMS, `helm test`.
  Secrets and keys are referenced, never generated. Unsafe configurations
  are refused at render time (`ci/check-refusals.sh`).
- CI job `helm`: `helm lint --strict` and render for every CI values file,
  kubeconform strict validation, the refusal checks, and an install on kind
  verified with `helm test` and `tools/verify_deployment.py`.
- The image now includes the PostgreSQL driver (`PV_DB_PACKAGES`) and the
  AWS KMS client (`PV_KMS_PACKAGES`). Without the driver every pod on
  PostgreSQL failed at start-up, which the kind install found
  (`tests/test_image_dependencies.py`, CI `docker` job).
- Fixed: `tools/verify_deployment.py` failed every PostgreSQL deployment
  (it accepted only `durable (sqlite)`). Found by running the API with the
  chart's environment. (`test_a_postgresql_deployment_passes`)

### Ledger backups that prove their restores (production readiness, phase 1 step 6b)
- `python -m agent_dna.backup backup|verify|restore`: PostgreSQL
  (`pg_dump`/`pg_restore`) and SQLite (online backup API). The manifest
  records the dump's SHA-256 and a per-table fingerprint taken from the
  same exported snapshot as the dump, so backups under live writes are
  exact; it can be signed with a local or KMS key. Restore refuses a
  non-empty target and reports success only if every table matches and
  every decision chain verifies.
- CI installs the PostgreSQL 16 client tools and runs the restore drill,
  including a backup taken while agents keep deciding.
- Runbook: `docs/operations/BACKUP.md`. Tests: `tests/test_backup.py`
  (the live-write test fails without the shared snapshot).

### Signing keys in AWS KMS or Google Cloud KMS (production readiness, phase 1: KMS)
- `agent_dna/key_custody.py`: one Ed25519 signer interface with local, AWS
  KMS (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, RAW) and Cloud KMS
  (`EC_SIGN_ED25519`) custodians. `PV_EXECUTION_SIGNER_KEY`,
  `PV_RECEIPT_SIGNING_KEY`, `PV_DISPATCH_WITNESS_KEY` and the receiver kit's
  `PV_RECEIPT_KEY_FILE` accept `awskms:` / `gcpkms:` references. Signatures
  are byte-identical to local signing; each KMS signature is verified
  locally before use; Cloud KMS CRC32C fields are checked; AWS documents
  over 4096 bytes are refused, never pre-hashed.
- `/v1/authorize` now takes the signer's key id from the bundle entry that
  is that key with `execution_authorization_signer` (it assumed the first
  bundle key); a key the bundle does not pin answers 503. A signer failure
  at mint is `AUTHORIZE_SIGNER_UNAVAILABLE` (503) and leaves no claim.
- `tools/kms_smoke.py` checks a real KMS key and prints its public key for
  the trust bundle. Extra `kms-aws` (boto3); Cloud KMS needs
  `google-cloud-kms`.
- ADR 0023. Tests: `tests/test_key_custody.py`,
  `tests/test_authorize_kms.py` (AWS requests validated against AWS's
  published API model).

### Receiver gate authenticates who presents a permit (production readiness, phase 1: mTLS)
- Permit spec `pv-execution-authorization/0.2-experimental` binds
  `expected_presenter_identity_digest`: the SHA-256 of the TLS client key
  (SPKI, RFC 7469 pin-sha256) that may present it. 0.1 permits stay valid.
- `PV_PRESENTER_BUNDLE`: the operator pins presenter keys per agent. With
  it, `/v1/authorize` requires `presenter_identity_digest`, refuses one not
  pinned for the authenticated agent, and mints 0.2; without it a
  requested presenter is refused rather than dropped.
- The receiver gate refuses a 0.2 permit unless the request arrived over
  mTLS with the bound key (checked after the signature, before the
  ledger, so a thief's attempt does not burn the permit);
  `PV_RECEIVER_REQUIRE_PRESENTER=1` also refuses 0.1 permits.
  `agent_dna/receiver/tls.py` serves the gate over mTLS and exposes the
  verified client certificate (also read from the ASGI `tls` extension);
  `python -m network.receiver_kit.serve` runs the kit with it. The TLS
  sidecar transport takes a client certificate and reports the digest to
  request.
- ADR 0022. Tests: `tests/receiver/test_presenter.py`,
  `tests/receiver/test_presenter_mtls.py` (real TLS handshakes),
  `tests/test_authorize_presenter.py`.

### Two API processes on one PostgreSQL, under load and failure (production readiness, phase 1 step 5)
- `tests/multi_instance/`: a harness that runs real `uvicorn` processes on
  one database and balances requests across them, and six tests: budget,
  one permit per decision, maker≠checker across processes, SIGKILL of a
  process mid-load, a database outage, and an outcome reported on the
  other process. Sandbox latency and throughput in
  `docs/benchmarks/MULTI-INSTANCE.md`.
- Fixed, found by these tests:
  - With PostgreSQL, two processes deciding for one agent forked the
    decision chain and the store refused the second write (HTTP 500).
    `PV_DATABASE_URL` now always uses the multi-writer recorder (chain head
    read and extended inside the store transaction).
  - In multi-writer mode, `/v1/outcome`, `/v1/lineage`, `/v1/records`,
    `/v1/blocked`, `/v1/divergent` and `/v1/verify` read a per-process
    snapshot taken at start-up: an outcome for a newer decision returned
    404, and `/v1/verify` reported integrity without checking new records.
    They now read the store.
  - A request that lost a race for the last of a grant's budget was
    BLOCKed with "agent suspended: grant_spend_fault", although nothing was
    suspended. It now gets the ordinary budget refusal (require_approval).
    A real spend fault still blocks, without claiming a suspension.
  - While the database refused connections, each request waited 30 s for
    a connection. `PV_DATABASE_TIMEOUT` (default 5 s) bounds the wait;
    `PV_DATABASE_POOL_SIZE` (default 10) sets the per-process pool.

### Shared agent baselines and cross-agent windows (production readiness, phase 1 step 4)
- With `PV_DATABASE_URL` set, each agent's drift baseline (the last
  capability it was allowed to run) and the cross-agent (CABI) execution
  windows live in PostgreSQL, so every API instance evaluates an agent
  against the same state. Window bounds and LRU eviction match the
  in-memory store exactly; appends to one execution are serialised, so
  when an initiate and a self-approval race on two instances, at least one
  is blocked. `RuntimeMonitor(state=..., max_events=...)` and
  `CrossAgentEnforcer(window_store=...)` take the storage as a parameter.
  (`tests/test_pg_shared_state.py`, 6 tests; the race test fails without
  per-execution serialisation)

### Fixed: API memory grew with every decision
- The API keeps one monitor per agent for its lifetime, and each monitor
  kept every event it processed. History is now capped at 256 events per
  agent; decisions themselves are in the decision store.
  (`test_event_history_can_be_bounded_for_long_running_servers`)

### PostgreSQL lineage, circuit breaker and replay (production readiness, phase 1 step 3)
- With `PV_DATABASE_URL` set, the lineage and circuit-breaker ledgers live
  in the same PostgreSQL database as the decision ledger; no SQLite file is
  created. They keep one copy of their logic: `agent_dna/pg_compat.py`
  gives them a connection-shaped view of the pool and keeps SQLite's
  "one writer per ledger" rule with a transaction advisory lock, released
  even if a statement fails. Ledger SQL is now portable (`ON CONFLICT`
  upserts, `RETURNING`). `PV_REPLAY_DB` accepts a `postgresql://` URL for
  opt-in replay inputs (kept in a separate database). The breaker now opens
  after the decision store.
  (`tests/test_pg_ledgers.py`, 10 tests; the cap and chain tests fail
  without the lock)

### PostgreSQL grant spend and revocation (production readiness, phase 1 step 2)
- With `PV_DATABASE_URL` set, grant budgets and grant revocations live in
  the same PostgreSQL database as the decision ledger, so every API
  instance shares one budget and one revocation list. Spend is a
  check-and-add under a row lock (`SELECT ... FOR UPDATE`), amounts stay
  canonical decimal strings, and revoking suspends every permit already
  minted under the grant. `pv grants revoke|revoked --db` accepts a
  `postgresql://` URL. The runtime manifest reports `durable (postgresql)`.
  (`tests/test_pg_grants.py`, 7 tests; the budget test fails without the
  row lock)

### PostgreSQL decision ledger (production readiness, phase 1 step 1)
- `agent_dna/pg_store.py`, `PV_DATABASE_URL`: the decision ledger (records,
  signature envelopes, permit and approval single-use claims, one mint per
  decision, suspensions, chain heads) on PostgreSQL with the SQLite store's
  contract. Canonical record bodies are stored verbatim, so exports are
  byte-identical. Uniqueness is enforced by the same constraints; where
  SQLite relied on BEGIN IMMEDIATE serialising all writers, narrow
  transaction advisory locks order mint against execution outcome (per
  decision) and suspension against consume (per scope). Mint replay rules
  are now one shared function for both backends, and the revocation list
  reads through the store instead of its connection. Optional extra
  `postgres`; CI runs the suite against PostgreSQL 16.
  (`tests/test_pg_store.py`, 16 tests including two that fail without the
  locks)

### Fixed: audit connector sign-in stuck in the browser
- The sign-in page's CSP allowed form submission only to itself; browsers
  apply `form-action` to the redirect that follows the POST, so after a
  successful sign-in the user stayed on our page and retries said
  "expired". `form-action` now also allows the registered redirect origin.
  Sign-in links last 30 minutes, and a used link says "Already signed in".
  (`test_login_page_lets_the_browser_follow_the_redirect_to_claude`; also
  checked in headless Chromium)

### PrivateVault Audit connector: OAuth 2.0 sign-in
- `agent_dna/audit_connector/oauth.py`, `--public-url`: the connector is its
  own authorization server. Unauthenticated MCP calls get `401` with a
  `resource_metadata` pointer; protected-resource and authorization-server
  metadata are served; clients register by DCR; `/authorize` requires PKCE
  S256; users sign in with their organisation's audit-scoped key, checked
  live against the API (a full-scope key is refused); codes are single use;
  refresh tokens rotate and the old pair is revoked; tools run with the
  signed-in user's key, which never leaves the server. Registration accepts
  only Claude's callback, loopback redirects, or operator-listed URIs.
  Hosted mode requires an https public URL. Token state is in memory
  (restart signs users out). (`tests/audit_connector/test_audit_connector_oauth.py`,
  end to end over HTTP with the official MCP client)

### PrivateVault Audit: read-only MCP connector
- `agent_dna/audit_connector/`: Streamable HTTP MCP server over the
  audit-scope API (`/v1/audit/export`, `/v1/verify`, `/v1/ops/summary`,
  `/v1/revocations`). Tools: `list_blocked_actions`, `list_agent_actions`,
  `get_decision`, `verify_audit_trail`, `activity_summary`,
  `list_revocations`; each has a title and `readOnlyHint`. Read-only is
  enforced by the credential too: the server holds an audit-scoped key.
  API failures reach the user as actionable tool errors that never echo
  the key. Binds to loopback only until user authentication (OAuth) is
  added. (`tests/audit_connector/test_audit_connector.py`, including an
  end-to-end run with the official MCP client over Streamable HTTP)

### Enterprise treasury demo on the existing stack
- `demos/treasury/`: two Claude agents with their own identities, API keys
  and grants (accounts payable, treasury) work a 16-action queue at USD
  magnitudes through the shipped controls: `/v1/decide` with a two-persona
  policy merged into one file (counterparty master, unverified bank
  details, 10M hard cap, per-agent authority, daily vendor aggregate,
  hourly velocity, business hours, maker-checker above 1M, split pattern
  above 1M aggregate), the approval bridge with a pinned treasury approver
  (`approve.py --unpinned` shows an untrusted key refused), per-agent
  permits and sidecars, the receiver gate, the receipt chain, the sealed
  decision export, and `PolicyReplay` with opt-in field retention as the
  deterministic replay check. Attacks: a compromised tool rewriting the
  beneficiary account after the decision, a replay of a used permit, and
  the treasury agent's sidecar handed the AP agent's permit. Naive and
  policy prompt modes; live table, impact banner from the rows, both
  verifiers OK then one byte changed FAIL, auditor export (`decisions.jsonl`,
  `receipts.jsonl`, `summary-<mode>.md`), `runs/<ts>-<mode>.jsonl` with
  `--replay`. Only the bank API and vendor master are mocks.
  (`tests/demos/test_treasury.py`; one opt-in real-model test)
- `docs/ROADMAP.md`: the receiver gate does not authenticate the
  presenting agent (per-agent mTLS client certificates bound into the
  permit is the planned fix); policy replay is library-only; approvals are
  single-approver, no quorum.
### Added — secure profile in one command; retest 2 (2026-10-16) findings

- `tools/init_secure_profile.py` provisions API keys, grants, the execution
  signer, an independent dispatch-witness/closure key, the trust bundle and a
  0600 `secure.env`; the API starts under `PV_SECURE_PROFILE=1` from it and
  `tools/verify_deployment.py` passes (tested end to end). Nothing secret is
  printed; existing directories are refused unless `--replace-existing`.
- Shell guard: `curl --data-urlencode name@file` (N16), secrets in
  environment variables such as `"$API_TOKEN"` (N12), bare `env`/`printenv`
  and `/proc/*/environ` count as secret egress; `tar --remove-files`,
  `rsync --remove-source-files/--delete*` and `git clean` set `destructive`.
  The 19 new variants are pinned in `tests/test_shell_guard.py`.

### Fixed — external retest findings (2026-10-16)

- Shell guard blocks credential staging (`cp`/`ln`/`tar`/`base64`/... or a
  redirect writing a credential-like file): retest E06 (symlink) and E10/E11
  (copy-then-send) no longer get a clean path.
- `examples/config/shell-policy.json`: `destructive` flag rule (`find -delete`,
  V10), unlisted programs blocked before approval rules, interpreters running
  script files need approval (V11). The full retest bypass table is pinned in
  `tests/test_shell_guard.py`.
- Test collection no longer aborts when the `docker` binary is missing.
- `tools/platform_demo.py` configures its own grants and ignores `PV_*`
  settings left in the caller's shell.

### Added — shell guard (external test findings S07, S11c, S12)

- `agent_dna/shell_guard.py`: for `PV_SHELL_CAPABILITIES` (default
  `shell.exec`) the runtime derives `evidence.shell` from the action's own
  argv/command, unwrapping env/sudo/timeout/xargs/nice/find -exec/busybox and
  nested `sh -c`. Callers cannot author it.
- Default deny, no policy needed: unparseable commands, inline code
  (`sh -c`, interpreter `-c/-e`, `eval`, `$(...)`, shell reading stdin) and
  network tools given credential-like files are BLOCKed
  (`triggered_by=shell_guard`). `PV_SHELL_ALLOW_INLINE=1` lifts only inline.
- Policy operators `any_in` / `any_not_in` for list fields;
  `examples/config/shell-policy.json`.
- `PV_UNGRANTED_DECISION=block|require_approval`; secure profile defaults to
  block for capabilities with no grant.

### Fixed — MCP gateway works with standard MCP clients (external test, 2026-10-15)

- `python -m agent_dna.gateway` now loads `RuntimeConfig.from_env()`; it
  previously ignored `PV_POLICY_FILE`, `PV_GRANTS_FILE`, `PV_DB_PATH` and the
  trusted keys. Bad configuration exits 1 with a message.
- stdio speaks newline-delimited JSON (MCP spec) by default on both the
  client and upstream side; `--framing content-length` keeps legacy clients.
- Upstream replies already buffered in the pipe are no longer mistaken for
  a timeout (raw-fd reads); upstream stderr no longer fills an unread pipe.
- Notifications get no response (JSON-RPC 2.0).
- `data/privatevault.db` is no longer tracked; `examples/config/grants.json`
  shows the `PV_GRANTS_FILE` format and the loader error points to it.

### Live refund agent demo: real Claude, real services over HTTP
- `demos/live_checkout/`: a Claude refund agent works a 15-request queue
  (`refund_queue.json`) through three real processes: the PrivateVault API
  with a six-rule policy (refund <= original, payee must be the original
  instrument, one refund per order, 3 per customer per day, approval above
  20,000, hard cap 2,00,000), the receiver gate from the receiver kit, and
  a mock payments API. A human approver in a second terminal signs
  `approval_v01` artifacts with its own key. The tool resolves the facts the
  rules read from the order ledger and from what the payments API actually
  paid; the model only names order, amount and payee. The queue carries
  every rule violation, a social-engineering message, a compromised tool
  that rewrites 3,000 to 30,000 after the decision (refused by the sidecar
  and by the gate), and a replay of request #1's permit (409). Live table,
  end screen with the independent verifier (OK, then one byte changed,
  FAIL), an impact banner computed only from the run's rows, Anthropic
  cost, and `runs/<timestamp>.jsonl` with `--replay` for an offline
  re-render. (`tests/demos/test_live_checkout.py`: services as subprocesses,
  scripted model, approver as a separate process, banner arithmetic checked
  against the rows; one opt-in real-model test behind `PV_LIVE_AGENT_TESTS=1`)
- `network/receiver_kit/config.py`: `PV_TRUST_BUNDLE_FILE` pins a bundle
  file instead of deriving one from the issuer values, so the API, sidecar
  and gate share one bundle with signer and witness keys. A file that is not
  a trust bundle, lacks a signer key, or disagrees with the issuer values
  refuses to start the gate.
  (`tests/network/test_receiver_kit.py::test_trust_bundle_file_is_pinned`,
  `::test_trust_bundle_file_refuses_malformed_or_mismatched`)
- `agents/core/approval.py`: `ApproverKit` accepts persisted keys so an
  approver can sign from its own process. `demos/agent_checkout/checkout_api.py`
  gains `GET /orders` and an order hook. `pyproject.toml`: optional extra
  `live` with the `anthropic` SDK.

### Agent checkout demo for payment gateways
- `demos/agent_checkout/`: one command (`uv run python demos/agent_checkout/run.py`)
  runs a procurement agent against a mock payment-gateway order API
  (`order_id`, `amount`, `currency`, `merchant_id`, `callback_url`) with the
  receiver gate in front of it. An 18,500 INR order is approved, minted,
  admitted once; an amount changed to 85,000 after approval, a payee swapped
  to M-9999, and a replay of the consumed permit are refused by the sidecar
  and the gate (`RECEIVER_WIRE_MISMATCH`, `RECEIVER_PERMIT_CONSUMED`); a
  2,50,000 request over the hard cap is blocked at decide with a signed
  approval in hand; receipts are exported and pass the independent verifier;
  the same five requests against the bare API all become orders. Writes a
  self-contained `report.html` timeline. `INTEGRATION.md` lays out reverse
  proxy, in-process middleware, and verify-endpoint integrations with
  effort. The README states what is mocked. (`tests/demos/test_agent_checkout.py`,
  including a tampered-receipts adversarial case)
- `agents/core/harness.py`: `Harness.start(upstream_factory=...)` lets a demo
  put its own mock behind the receiver gate; the default is still the receiver
  kit's stub. (`tests/demos/test_agent_checkout.py::test_harness_custom_upstream_is_gated`)

### Proof, P4 to P6: one command, threat model, evaluation guide
- `proof/run_all.py` runs P1 to P3 in process and exits 0 only if every
  proof holds; `proof/docker-compose.yml` runs it in a container with no
  network. (`tests/proof/test_run_all.py`; the container run is opt-in with
  `PV_PROOF_DOCKER_TESTS=1` and runs in the ubuntu Docker CI job)
- `docs/THREAT-MODEL.md`: one row per attack with the control, the ADR,
  and the pinning test names; explicit non-goals. `docs/EVALUATE.md`: a
  one-day evaluation guide with success criteria and a mermaid
  architecture diagram. `tests/proof/test_docs_pin_tests.py` fails if
  either document cites a test or path that does not exist.

### Proof, P1 to P3: comparison, before/after, prompt injection
- `proof/compare/`: the same attack (valid credentials, amount or payee
  changed after approval) against an LLM guardrail stub, an API gateway
  with an OPA-style amount cap, strict idempotency keys, and the
  PrivateVault receiver gate. The first three admit it; the gate refuses
  with `RECEIVER_WIRE_MISMATCH`. Every control admits the honest request.
  `RESULTS.md` is regenerated by the run and pinned by a test; the
  10,000-cap counter-case is a test. (`tests/proof/test_compare.py`)
- `proof/before_after/`: finance ops with PrivateVault off (the upstream
  receives 48,000, no decision record exists) and on (refused by the
  sidecar and by the receiver gate; the upstream receives only the
  approved 18,000). (`tests/proof/test_before_after.py`)
- `proof/injection/`: an invoice whose notes instruct the model to pay
  `ACCT-ATTACKER`; a scripted instruction-following model obeys. Without
  PrivateVault the attacker is paid; with it the payee is blocked at decide
  (`unknown-payee`), and a payee injected after approval is refused by the
  sidecar and the receiver gate. (`tests/proof/test_injection.py`)
- Supporting changes: `Harness.start(tools=...)` lets a proof use a
  variant of a persona's tools; the receiver kit's stub upstream records
  the parsed body (`body_json`) so the proofs can print the amount and
  payee that arrived. No change to `agent_dna/`.

### Agents, phase A: personas 2 and 3
- `agents/personas/interior_design/`: client quotes and vendor purchase
  orders in INR. A PO up to 50,000 to an approved vendor is allowed under
  a budgeted grant; above 50,000 needs the studio owner's approval; above
  200,000 or to an unapproved vendor is blocked. The demo shows a vendor
  swapped after approval refused by the sidecar and by the vendor
  network's gate. (`tests/agents/test_interior_design.py`)
- `agents/personas/property_broker/`: listings, follow-ups, viewings, and
  token payment requests at the escrow partner. The only permitted payee
  is the brokerage escrow account: any other payee is blocked at decide;
  above 100,000 needs the principal broker's approval; above 500,000 is
  blocked. The demo shows a payee changed after approval refused by the
  sidecar and by the escrow gate, and a replay refused.
  (`tests/agents/test_property_broker.py`)
- Both are YAML plus a tool list on the unchanged template; no core
  changes.

### Agents, phase A: template and persona 1 (finance ops)
- `agents/core/`: a config-driven agent template where the model only
  proposes. Read tools run locally; external tools run under a single-use
  clearance issued after an ALLOW; money tools never execute locally and
  take effect only as the sidecar dispatch of the permitted bytes. A
  persona is `persona.yaml` (identity, tools, grants, policy rules,
  approvers) compiled to `PV_POLICY_FILE` and `PV_GRANTS_FILE`; the engine
  decides, the template never does. `ApproverKit` signs real
  `approval_v01` artifacts for the ADR 0020 bridge. An in-process harness
  assembles the API, the receiver gate over the receiver kit's stub
  upstream, the sidecar with a demo-grade transport, and per-run keys.
  `AnthropicModel` is opt-in and untested. Not shipped in the wheel.
  (`tests/agents/test_template.py`)
- `agents/personas/finance_ops/`: invoice to payment instruction in INR.
  Up to 5,000 with a matching PO is allowed under a budgeted grant; above
  5,000 or without a PO needs the CFO's approval; above 50,000 or an
  unknown payee is blocked. The demo shows a changed amount refused by the
  sidecar before any byte and by the receiver when the sidecar is bypassed,
  a replay refused, and the receiver's receipts passing the independent
  verifier. (`tests/agents/test_finance_ops.py`, including
  `::test_demo_runs_green`)

### Approval bridge (ADR 0020)
- `/v1/decide` accepts an `approval` block (approval_v01 request, signed
  artifact, approver authority receipt). `agent_dna/approval_bridge.py`
  admits it only if it verifies against the operator-pinned approver
  bundle (`PV_APPROVER_TRUST_BUNDLE`), binds the exact execution action
  and organisation, names this agent, satisfies separation of duties
  (approver is not the agent, its principal, or the caller), and has not
  been used before (durable single-use claim in `approval_consume`, same
  construction as permits). A policy or authorization REQUIRE_APPROVAL
  then becomes ALLOW with `triggered_by = "approval"` and the artifact
  digest sealed in `approval_ref`; `/v1/authorize` mints only with that
  digest (`AUTHORIZE_APPROVAL_MISMATCH` otherwise). Refused approvals
  never change the verdict and are not consumed; BLOCK is never
  overridden; a plain ALLOW does not burn the approval; an approval with
  no bundle pinned or on an audit-only decide is refused outright (422).
  (`tests/test_approval_bridge.py`, `tests/test_api_approval_bridge.py`)

### Hardening: bounded request size and JSON nesting
- A few thousand nested brackets inside a 1 MB body raised `RecursionError`
  in JSON parsing on `/v1/decide` and `/v1/authorize` (a 500 per request),
  and the app had no body size limit of its own. `agent_dna/request_bounds.py`
  adds an outermost ASGI middleware: bodies over `PV_MAX_REQUEST_BYTES`
  (default 1 MiB, validated at startup, 1 KiB to 64 MiB) are 413 before
  parsing, with or without `Content-Length`; JSON nested deeper than 32
  levels is 400 `REQUEST_JSON_TOO_DEEP`. In the library,
  `_validate_json_value` and `canonicalize` enforce
  `MAX_JSON_NESTING_DEPTH = 32` and `strict_json_loads` turns the decoder's
  `RecursionError` into `AuthorityFormatError`, so the receiver gate now
  answers a deep permit header with `RECEIVER_PERMIT_MALFORMED` (403, with a
  receipt) instead of `RECEIVER_INTERNAL_ERROR` (500).
  (`tests/test_request_bounds.py`, `tests/test_json_depth_bound.py`)

### Hardening: authorization window validated at startup
- `/v1/authorize` parsed `PV_AUTHORIZATION_TTL_SECONDS` with a bare `int()`
  on every request: a non-integer value made every mint a 500, zero or a
  negative value minted a permit that failed its own schema, and a large
  value silently minted long-lived permits. The TTL (1 to 300 s, default
  60) and the new `PV_AUTHORIZATION_NOT_BEFORE_LEEWAY_SECONDS` (0 to 30 s,
  default 0) are now parsed once in the lifespan; a bad value refuses to
  start. The leeway moves `not_before` and `issued_at` back from mint time
  and never moves `expires_at`; it is the mint-side counterpart of the
  sidecar's strict clock.
  (`tests/test_authorize_window_config.py`)

### Hardening: sidecar validity window uses the sidecar's clock
- `ExactByteHttpDispatcher` judged `not_before`/`expires_at` against the
  caller-supplied `ExactByteContext.at_time`, so a caller echoing the
  mint time could dispatch an expired permit later. The window is now
  judged by the dispatcher's own `clock` (operator-injectable, must return
  an aware datetime), which also stamps `consumed_at`, `observed_at` and
  `closed_at`. No skew tolerance at the sidecar by design: the witness
  must lie inside the window the verifier checks, so any leeway belongs
  at mint time. `at_time` stays on the context as informational only.
  See `SECURITY.md`, "Fixed issues".
  (`tests/connector/test_exact_byte_http.py::test_expired_permit_refused_even_when_caller_claims_earlier_time`,
  `::test_not_yet_valid_permit_refused_even_when_caller_claims_later_time`,
  `::test_operator_clock_decides_validity`,
  `::test_sidecar_clock_is_strict_and_stamps_the_evidence`)

### Network kit, phase 1: receiver kit
- `network/receiver_kit/`: run the ADR 0019 receiver gate as a reverse proxy
  on a partner's own infrastructure with a partner-generated receipt key.
  Configuration is environment only and fails closed; the trust bundle is
  derived deterministically from the issuer organisation and public keys so
  gate and issuer agree on its digest. Ships `keygen.py`, a demo upstream,
  `send_test.py` (valid permit admitted once, amount changed refused, replay
  refused, upstream never sees the second), `export_receipts.py`, a compose
  file, and a one-page quickstart. No change to `agent_dna/`.
  (`tests/network/test_receiver_kit.py`)
- Receiver kit entrypoint: the container starts as root only to copy the
  mounted receipt key into a tmpfs owned by the gate user (mode 0400) and
  drops to uid 10001 with `setpriv --no-new-privs` before the gate starts;
  the ledger moves to a named volume. Closes the Linux dead end where a
  bind-mounted 0600 key keeps the host uid and the fixed container user
  cannot read it (R1 #10). An unreadable key is now a `ConfigError` with
  guidance.
  (`tests/network/test_receiver_kit.py::test_gate_does_not_depend_on_host_uid_matching_the_container_user`,
  `::test_unreadable_key_file_error_is_actionable`,
  `::test_entrypoint_hands_key_to_gate_user_and_drops_root` with
  `PV_KIT_DOCKER_TESTS=1`)

### Receiver gate (ADR 0019)
- `agent_dna/receiver/`: the system of record verifies and consumes the
  permit. `ReceiverGate` admits a request only if it carries a permit
  signed under the operator-pinned trust bundle that binds this receiver,
  the exact `METHOD path`, the exact body (which must be the signed
  action parameters), the validity window, and a receiver-owned
  single-use claim. Direct calls that skip the sidecar are refused
  (`tests/receiver/test_receiver_gate.py`).
- Signed, hash-chained receiver receipts for every admitted and refused
  request, keyed by the receiver operator (independent of PrivateVault
  keys). `tools/verify_receiver_receipts.py` verifies them without
  importing `agent_dna`
  (`tests/receiver/test_receiver_independent_verifier.py`).
- `ReceiverGateMiddleware` (ASGI) and `ReceiverGateProxy` (reverse proxy
  for unmodified upstreams); `ExactByteHttpDispatcher(attach_permit_header=True)`
  presents the permit without changing bound bytes
  (`tests/receiver/test_receiver_http.py`).

### LangGraph human-in-the-loop example
- Add `examples/langgraph_hitl/`: a LangGraph propose -> approve (`interrupt()`)
  -> execute agent that binds a human approval to the exact tool call with a
  single-use execution permit. State edited while paused is refused at
  execute time, recorded as a BLOCK, and the permit is burned.
  Covered by `examples/langgraph_hitl/test_hitl_binding.py` (edit while
  paused, replay, parallel calls, reviewer edit, expiry). This is an example
  and is not collected by the default CI test run. It re-implements the
  `/v1/authorize` mint sequence in process and uses a throwaway grant as the
  approval-to-ALLOW bridge; it does not change any PrivateVault behaviour.
  `bench_latency.py` measures the added latency of the check.

### MCP SDK 2
- Require `mcp>=2.2,<3` in both dependency manifests and refresh `uv.lock`.
  Migrate servers, clients, result fields, and HTTP setup to the SDK 2 APIs.
- Read MCP identity from the explicit request context. HTTP requests without
  a bearer key cannot inherit a privileged static/stdio key. Legacy and modern
  protocol modes, concurrent identities, signed refusals, and late-registered
  tools are covered by `tests/connector/test_mcp_adapter.py` and
  `tests/connector/test_mcp_http_identity.py`.

### Dashboard dependencies
- Pin nanoid 3.3.18 to fix GHSA-2v37-7h3g-55p8. CI runs the
  bounded zero-size regression in `dashboard/tests/dependencies.test.cjs`
  and fails on high or critical npm advisories.

### Wire-binding integration
- Integrate first-mint action/body consistency checks from the existing
  wire-action-binding branch and migrate the JSON-body examples.
- Preserve generic connector/gateway policy and audit behavior using an
  explicit non-mintable context marker. Historical context digest reading
  does not upgrade authority (`tests/test_wire_action_binding.py`).
- Match runtime serializer validation to the permit/witness schemas;
  restore full connector, gateway, shadow, Campfire and demo integration.

### Proof reporting
- Missing live audit evidence now fails the mandatory proof gate.
- Grouped pytest skips count every case. Regression coverage:
  `tests/test_prove_manifest.py`.

### Security
- **Mint INDETERMINATE race:** `claim_or_replay_mint` re-reads execution
  status inside `BEGIN IMMEDIATE`, so an indeterminate outcome that
  commits first cannot create a permit
  (`tests/test_authorize_indeterminate_race.py`).
- **Stored trust-bundle replay:** the mint ledger stores the canonical
  original trust bundle and digest with the authorization. Replay
  returns that pair and never substitutes the current process bundle.
  Legacy rows without a bundle fail closed
  (`AUTHORIZE_PERMIT_TRUST_BUNDLE_MISSING`;
  `tests/test_authorize_trust_bundle_replay.py`).
- **Rotation action binding:** `rotate_and_record` derives the new
  public key before decide and binds `new_public_key` into
  `AgentAction.arguments`. A mismatched returned key cannot reuse the
  earlier decision (`tests/test_key_rotation_provisioned.py`).
- **Authorize storage failures:** SQLite operational/database errors on
  mint return HTTP 503 with `AUTHORIZE_STORE_UNAVAILABLE`; unexpected
  faults return 500; clients never see paths, SQL, or exception text
  (`tests/test_authorize_mint_storage_errors.py`).
- **PV-01 amount required on budgeted/capped paths:** omitted, `None`,
  and empty amounts on budgeted grants and amount-capped breakers
  BLOCK with `INVALID_AMOUNT` before spend, reservation, or
  observation mutation. Unbudgeted grants and uncapped breakers keep
  their previous missing-amount behaviour. Excessive precision is
  rejected on the shared Decimal coercer
  (`tests/test_amount_requirement.py`).
- **PV-02 one live permit per decision:** the first valid
  `/v1/authorize` atomically stores one signed execution
  authorization. Identical authenticated replay returns the stored
  bytes (same id, nonce, signature). Changed bindings hard-refuse
  with `AUTHORIZE_PERMIT_BINDING_CONFLICT`. Consumed, expired, and
  INDETERMINATE permits are not replaced
  (`tests/test_authorize_mint_claim.py`). Administrative remint
  recovery is deferred and fail-closed.
- **PV-06 UAAL monetary conservation:** action and invoice amounts use
  the shared Decimal coercer. `+inf`/`-inf`/`NaN`/bool/negative/
  malformed values fail closed as invalid evidence, not as an
  ordinary mismatch (`tests/test_uaal_monetary_coercion.py`).
- **PV-07 caller-provisioned key rotation:** `rotate_key` /
  `rotate_and_record` require `new_seed_hex`, validate it, sign and
  verify a deterministic challenge, then persist the rotation
  envelope. The seed is never returned or logged. Omitted or invalid
  seed fails before a successful rotation record
  (`tests/test_key_rotation_provisioned.py`).
- **Amount coercion:** grant budgets and circuit-breaker caps reject
  bool, NaN, ±inf, negative, non-numeric, and over-ceiling amounts
  with `INVALID_AMOUNT` before any spent or breaker-row mutation.
  Coercion is `Decimal`, not `float()` (`tests/test_amount_coercion.py`).
- **Stdio env isolation:** MCP stdio children receive an explicit
  environment allowlist, not a copy of `os.environ`
  (`tests/test_stdio_env_isolation.py`).
- **Sidecar production audit (two-stage egress):** offline execution
  authorization verify before any socket; per-dispatch TLS sessions
  (no shared live connection); credential attachment requires
  allowlisted destination and audience (`PV_EGRESS_ALLOWED_*`);
  closure records the observed HTTP status; response body/header
  bounds; `closure_signer` required on the witness public key with no
  fallback (`tests/connector/test_exact_byte_http.py`,
  `tests/connector/test_sidecar_tls.py`,
  `tests/test_secure_profile.py`). In-process is not complete
  mediation — sole-egress plus network policy remain operator
  requirements.
- **MCP gateway bake-off hardening:** credential-session attribution
  plus fail-closed unattributed bypass; HTTPS-only (operator flag to
  allow `http://`); same-origin redirects re-decided; first-class DRP
  `indeterminate` and optional `response_digest`; `prompts/get` gated;
  production `undeclared_tool_policy=block`; in-process upstream
  test-only; named `https-egress` transport with freeze/decide/verify
  (`tests/gateway/test_bakeoff_hardening.py`,
  `tests/test_execution_feedback.py`).
- **MCP gateway phase 2 (protocol reality):** in-flight JSON-RPC calls
  are correlated by id (unmatched / duplicate ids fail closed);
  `resources/read` and `resources/subscribe` are gated; `prompts/get` is
  gated (see bake-off hardening); `sampling/createMessage` is refused; unknown
  methods are not forwarded; upstream size/depth caps, death/restart,
  shutdown, reconnect isolation, default-on TLS verify, cross-origin
  redirect refusal, and SSE byte bounds
  (`tests/gateway/test_protocol_hardening.py`).
- **Exact-byte egress adapter**: `ExactByteHttpDispatcher` pins
  `PV_EXECUTION_TRUST_BUNDLE_FILE` at construction (callers cannot
  select a trust root). Production uses a sidecar-owned HTTPS/TLS
  transport; peer identity is observed from the handshake; the
  dispatch witness is signed only after send. Outcomes are
  `NOT_SENT`/`CONTROL_FAILURE`, `EXECUTED`, and `INDETERMINATE`
  (`tests/connector/test_exact_byte_http.py`,
  `tools/adversarial_egress_demo.py`). Adapter conformance covers
  MCP + exact-byte (`tests/test_adapter_conformance.py`).
  Note: #52's changelog claimed the secure profile required signer
  and trust bundle before that was fully true; receipt signer/roots
  and the execution trust bundle are this change.
- **Secure-defaults profile**: `PV_SECURE_PROFILE=1` requires API keys,
  grants, receipt signer, trust roots, and
  `PV_EXECUTION_TRUST_BUNDLE_FILE`; forces cross-agent execution_id
  and loop-events required; refuses `PV_ALLOW_NO_AUTH`
  (`tests/test_secure_profile.py`). Platform compose enables it.
- **F-03 / F-04 / F-05 caller-controlled enforcement**: production
  composition attaches deny-all grants when `PV_GRANTS_FILE` unset;
  `authorizer=None` is fail-closed (not allow). Operator flags
  `PV_CROSS_AGENT_REQUIRE_EXECUTION_ID` and `PV_LOOP_EVENTS_REQUIRED`
  (on in platform compose) refuse missing `execution_id` /
  `security_events`. Control posture is written into decision evidence
  (`tests/test_caller_controlled_enforcement.py`).
- **F-01 authorize binding**: `POST /v1/authorize` requires
  `decision_id` and/or `record_hash`, loads the sealed decision, refuses
  unless ALLOW, and recomputes action/arguments/receipt digests against
  the record. Distinct reason codes; no disable flag
  (`tests/test_authorize_binding.py`).
- **F-02 consume ledger**: durable SQLite
  `execution_authorization_consume` table; successful
  `verify_execution_authorization(..., consume_ledger=...)` claims the
  id atomically (`BEGIN IMMEDIATE` + UNIQUE). Caller
  `already_consumed` may only tighten. Restart-safe
  (`tests/test_consume_ledger.py`).

### Added
- **Campfire hosted black-box evaluation pack**: source-free partner
  zip plus operator bootstrap (`tools/init_campfire_blackbox.py`,
  `tools/build_campfire_partner_pack.py`,
  `tests/test_campfire_blackbox.py`). The pack is a hosted interface,
  not complete mediation of Campfire's tool path. The evaluation
  runtime sets `PV_BASELINE_CAPABILITIES` so the sandbox write is on
  the synthetic baseline; default grant-plus-drift behaviour is
  unchanged. The normalized override is exposed on `GET /v1/runtime`.
  `/v1/outcome` `status=ok` requires `dispatched=true`; false or
  omitted dispatched fails closed with HTTP 409.
- **Multi-agent on the live decide path**: definitional dual-control +
  structural approval CABI attached by default (`PV_CROSS_AGENT=1`),
  escalation-only on HTTP `POST /v1/decide` and connector middleware when
  `execution_id` is declared; MCP forwards `_pv_execution_id`;
  `discover_loops` gates `POST /v1/authorize` when `security_events` are
  supplied (`tests/test_api_cross_agent.py`, `tests/test_dual_control.py`).
- **Self-hosted platform ops profile**: `GET /ready` store readiness,
  Prometheus decide-path metrics (`pv_decisions_total`, `pv_blocks_total`,
  `pv_decide_latency_seconds`, `pv_ready`), `GET /v1/ops/summary`,
  `docker-compose.platform.yml` (API + operator console + Prometheus),
  `tools/platform_demo.py`, `tools/init_platform_keys.py`, and
  `.well-known/security.txt`. Single-tenant self-hosted — does not claim
  SOC 2 / ISO / multi-tenant SaaS (`tests/test_platform_ops.py`).
- **PrivateVault Discovery Loop v1**: verified sealed history -> evidence-linked
  policy mining -> additive history and adversarial replay -> deterministic
  evaluation and structural probes -> ranked, human-reviewed PR proposals.
  Includes strict corpus/report schemas, full motivating record hashes,
  proposal notes, CLI, and an independent standard-library report verifier.
  It never applies policy; learned validation remains advisory and experimental
  Hodge/reachability probes remain quarantined (`agent_dna/discovery.py`,
  `spec/discovery-loop-v1/`, `docs/DISCOVERY-LOOP.md`,
  `tools/verify_discovery.py`, `tests/test_discovery.py`).
- **Agent Security Loop Discovery v1**: bounded deterministic analysis of
  cross-agent delegation, approval, invocation, dispatch, authorization reuse,
  causal ancestry, and repeated canonical actions. Strict JSON Schemas,
  deterministic witness paths and report digests, CLI exit-code contract,
  adversarial examples, an authority-boundary ADR, and malformed/replay/DoS
  regression coverage (`agent_dna/security/loop_discovery.py`,
  `spec/loop-discovery-v1/`, `docs/LOOP-DISCOVERY.md`,
  `tests/test_loop_discovery.py`).
- Operational trust invariant over real `InteractionEvent.trust` evidence,
  wired into the default cross-agent invariant engine. Material degradation is
  reviewable; severe degradation and malformed scores hard-block
  (`tests/test_trust_invariant.py`).
- Locked Python environment, strict typing gate for the security loop module,
  dashboard CI, CodeQL, Dependabot, release checklist, contribution policy, and
  repository-wide coding-agent security instructions.
- PrivateVault operator console replacing the generated Vite starter screen.
- **Authority Reachability v0.1-experimental**: deterministic blast-radius
  analysis over typed authority and company-knowledge graphs; explicit
  evidence classes; protected irreversible sinks; shortest-path witnesses;
  fail-closed conditions; direct-grant, issuer, and delegation-depth
  invariants; before/after change simulation; deterministic report hashes;
  signed report envelopes; JSON schemas; synthetic Agentforce vectors; and an
  offline runtime-coupled CLI
  (`experimental/authority_reachability_v01/`,
  `spec/authority-reachability-v01/`,
  `tools/pv_authority_reachability.py`; tests:
  `test_authority_reachability_v01.py`).
- **Authority Provenance v0.1-experimental**: strict trust-bundle, signed
  delegation-grant, and three-verdict receipt schemas; RFC 8785
  canonicalization over float-free I-JSON; Ed25519 key-usage enforcement;
  principal-and-key continuity; typed attenuation; independent authority and
  composition recomputation; runtime-coupled offline CLI; and two-axis authorisation
  readiness scan (`agent_dna/authority_v01.py`, `spec/authority-v01/`,
  `tools/pv_authority_cli.py`; tests: `test_authority_v01.py`,
  `test_authority_scanner_v01.py`).
- **pv-validation/1**: hash-sealed model-validation reports for the
  advisory drift layer — localized reliability by agent / capability /
  agent×capability with Wilson CIs, exact global-AUC within/between
  decomposition, calibration metrics (Brier, log loss, ECE) for
  declared probability scores only, label-shift vs concept-drift
  distinction with closed-form prior-odds correction, min-sample and
  class-count safeguards, independent-label requirement
  (`agent_dna/validation/`, `spec/validation/`,
  `docs/VALIDATION-MATH.md`; tests: `test_validation_*.py`).
- Stdlib-only validation verifier (`tools/verify_validation.py`),
  canonical vector with pinned hash (`test_validation_vectors.py`).
- `ValidationGuard`: optional runtime coupling via
  `PV_VALIDATION_REPORT` — tighten-only at the existing drift level,
  calibration warnings report-only, deterministic L0-L4 untouched
  (`test_validation_guard.py`).
- Real `LocalPolicyAdapter`: directory of YAML/JSON policies through
  the L2 `PolicyChecker`, deterministic order, fail-closed loading,
  evidence-honest skips (`test_local_policy_adapter.py`).
- Apache-2.0 `LICENSE`; threat-model `docs/SECURITY.md`;
  `CHANGELOG.md`.

### Changed
- Release metadata advanced to v0.4.0.
- Container runs as UID/GID 10001 and unauthenticated compose startup is no
  longer enabled by default.
- CI now gates Python formatting, linting, staged typing, the sealed proof run,
  spec vectors, dashboard lint/build, and a non-root container smoke test.
- README: status + 5-minute demo section; precedence list corrected
  to the 8-level contract (L2 customer policy was missing from the
  intro list; `spec/contracts/precedence-order.json` was already
  correct and CI-pinned).
- Packaging: `pyproject.toml` dependencies now exactly the imports of
  the core (removed unused sqlalchemy/alembic/cryptography); optional
  `[integrations]` extra for prometheus/kafka/redis/otel/pandas;
  `requirements.txt` mirrors core.
- `GitBundleAdapter` moved to `experimental/adapters/` with a
  deprecation shim — it was a non-firing stub presented as an adapter.
- docker-compose: healthcheck added so `--wait` gates on readiness.

### Fixed
- `/metrics` endpoint raised `NameError` on every call (undefined
  `body`/`content_type`); now serves Prometheus exposition with a
  stdlib fallback (`test_metrics_endpoint.py`).
