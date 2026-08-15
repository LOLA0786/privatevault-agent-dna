# Fineract lab counterparty

Apache Fineract as an independent system of record for the exact-byte HTTP
adapter. It is the counterparty, not a dependency. Do not vendor, fork, or
patch it.

Upstream: [apache/fineract](https://github.com/apache/fineract) (Apache-2.0).
Pinned image: `apache/fineract:1.11.0@sha256:d2da31748f5550b5ebe362b245283b555c71fc914623c29ec1534fe54487f954`
(manifest-list digest confirmed with `docker buildx imagetools inspect
apache/fineract:1.11.0`; GitHub latest is `1.15.0`, which has no Hub tag).
Postgres matches that tag's compose: `postgres:16.1`.

**Review date: 31 December 2026.** On that date this pilot is either promoted
to a supported integration with its own claim discipline, or removed. It does
not sit undecided.

## How to run

Allocate **6GB minimum** to Docker Desktop. Fineract + Postgres is heavy. An
OOM mid-boot looks like an API-shape bug; do not invent workarounds for that.

```bash
cd pilot/fineract
docker compose up -d
# wait until https://localhost:8443/fineract-provider/actuator/health is {"status":"UP"}
# first boot runs Liquibase; several minutes is normal
python3 seed.py
# from the repo root, after seed-state.json exists:
pytest -m pilot
```

`seed.py` is stdlib-only. It pins the container's self-signed cert to
`fineract-dev.pem` on first run and verifies later requests against that file.

Re-run `seed.py` is safe: clients and accounts are looked up by `externalId`.

## Verify before coding

Answers from apache/fineract **1.11.0** source, not from this brief. Where the
brief assumed something else, the source wins.

### 1. Base path and port

- HTTPS on **8443** (TLS is on; self-signed is expected).
- API base: `https://localhost:8443/fineract-provider/api/v1`
- Health: `https://localhost:8443/fineract-provider/actuator/health` → `{"status":"UP"}`

Source: `README.md` at 1.11.0 ("fineract (back-end) is running at
https://localhost:8443/fineract-provider/"; wait for actuator/health). JAX-RS
resources are mounted at `/v1/...` under `/fineract-provider/api`.

TLS: do not call `ssl._create_unverified_context` and do not set
`FINERACT_INSECURE_HTTP_CLIENT` on our client.

**Option taken: hostname checking stays on.** 1.11.0
`application.properties` already binds `FINERACT_SERVER_SSL_KEY_STORE`.
Compose `tlsgen` writes `tls/cert.pem` + `tls/fineract.p12` with SAN
`DNS:localhost` and `IP:127.0.0.1`. Fineract loads that PKCS12. Clients
connect as `localhost` with `ssl.create_default_context(cafile=tls/cert.pem)`
and `check_hostname=True`. The 1.11.0 image cert is not used, so we did
not need `check_hostname=False` and did not add a hosts alias for a
foreign CN.

Named tests: `tests/pilot/test_tls_pin.py`
(`test_hostname_checking_is_on`, `test_pinned_cert_rejects_a_different_ca`).
A different CA file must fail the handshake. Recreating the stack rotates
the cert — `docker compose down -v && docker compose up -d`, then re-seed.

### 2. Tenant header and default tenant id

- Header name: **`Fineract-Platform-TenantId`**
- Default tenant id: **`default`**

Source: `TenantAwareBasicAuthenticationFilter` at 1.11.0
(`TENANT_ID_REQUEST_HEADER = "Fineract-Platform-TenantId"`; missing header is
a 400). Query param `tenantIdentifier` is accepted as a fallback; we send the
header. Default id from `config/docker/env/fineract-common.env`:
`FINERACT_DEFAULT_TENANTDB_IDENTIFIER=default`. README community-app URL uses
`tenantIdentifier=default`.

Not `X-Mifos-Platform-TenantId`.

### 3. Default credentials and how to change them

**Application user (HTTP Basic), not a compose env:**

- Username `mifos`, password `password`
- Source: 1.11.0 `README.md` ("login using default username `mifos` and
  password `password`"). This is Liquibase demo data, not
  `FINERACT_HIKARI_*`.

To change the app password after boot, `PUT /fineract-provider/api/v1/users/{userId}`
with `password` and `repeatPassword` (`UsersApiResource`; "When updating a
password you must provide the repeatPassword parameter also."). There is no
compose knob for `mifos`/`password`.

**Database (compose):**

From `config/docker/env/postgresql.env` and `fineract-postgresql.env` at 1.11.0:

- Postgres superuser `root` / `skdcnwauicn2ucnaecasdsajdnizucawencascdca`
- App DB user `postgres` (created by `01-init.sh`)
- JDBC: `jdbc:postgresql://db:5432/fineract_tenants`
- Override both DB passwords in one shot: `FINERACT_DB_PASSWORD` in the
  environment when running `docker compose up`.

`01-init.sh` is copied from
`config/docker/postgresql/docker-entrypoint-initdb.d/01-init.sh` at 1.11.0 so
this directory does not need a Fineract checkout. It is not a Fineract patch.

### 4. Account-to-account transfer

Savings-to-savings only at 1.11.0. There is no generic "transfer" on the
savings resource.

```
POST /fineract-provider/api/v1/accounttransfers
```

Source: `AccountTransfersApiResource` `@Path("/v1/accounttransfers")`. Class
javadoc: "At present only savings account to savings account transfers are
supported." Template examples use `fromAccountType=2` (savings).

Body (`PostAccountTransfersRequest` in `AccountTransfersApiResourceSwagger`):

```json
{
  "fromOfficeId": 1,
  "fromClientId": 1,
  "fromAccountType": 2,
  "fromAccountId": 1,
  "toOfficeId": 1,
  "toClientId": 2,
  "toAccountType": 2,
  "toAccountId": 2,
  "dateFormat": "dd MMMM yyyy",
  "locale": "en",
  "transferDate": "14 August 2026",
  "transferAmount": 500,
  "transferDescription": "pv:<run_id>:<request_id or first 16 hex of action_digest>"
}
```

List transfers: `GET /fineract-provider/api/v1/accounttransfers`.
Captured live envelope (not a bare list; a bare list was never observed
at 1.11.0):

```json
{"totalFilteredRecords":2,"pageItems":[...]}
```

The join helper asserts that paged shape as expected and still accepts a
bare list so a surprise payload fails at the join with the expected keys
named. One transfer: `GET /fineract-provider/api/v1/accounttransfers/{transferId}`.
Live 1.11.0 response to POST: `{"savingsId":N,"resourceId":N}`. No extra
mandatory fields. Body above is unmodified from what worked.

`seed.py` does not transfer. It only creates clients, accounts, and the
deposit that funds A.

**Correlator (two hops, not a binding).** Case 4 does not read a description
off the savings transaction. A savings row produced by a transfer has these
keys and no description field of any kind (live 1.11.0):

`accountId` `accountNo` `amount` `chargesPaidByData` `currency` `date`
`entryType` `id` `interestedPostedAsOn` `isManualTransaction` `isReversal`
`lienTransaction` `originalTransactionId` `releaseTransactionId` `reversed`
`runningBalance` `submittedByUsername` `submittedOnDate` `transactionType`
`transfer`

The nested `transfer` object contains: `id`, `reversed`, `currency`,
`transferAmount`, `transferDate`, `transferDescription`.

`GET /v1/accounttransfers` returns the full transfer record including
`transferDescription`, `fromAccount`, `toAccount`, `fromClient`, `toClient`.

Join path:

1. Our chain → `transferDescription` on `GET /v1/accounttransfers` → transfer
   `id`. The string is one we choose (`pv:` plus a per-session `run_id`, then
   `request_id` or the first 16 hex of `action_digest`). Fineract stores it
   opaquely. That hop is not a cryptographic binding.
2. That transfer `id` → `transactions[].transfer.id` on the savings account.

Helpers in `tests/pilot/conftest.py`: `transfer_description()`,
`accounttransfer_ids_for_description()`, `savings_nested_transfer_ids()`.
Divergence in either hop is a failure. A match is not proof of exact-byte
identity.

### 5. Savings balance and transaction list

```
GET /fineract-provider/api/v1/savingsaccounts/{accountId}?associations=transactions
```

Source: `SavingsAccountsApiResource` `@Path("/v1/savingsaccounts")`,
`retrieveOne`. Associations `transactions` (or `all`) attach the transaction
collection. `summary.accountBalance` is the ledger balance
(`GetSavingsAccountsSummary` in the swagger class).

By external id: `GET /fineract-provider/api/v1/savingsaccounts/external-id/{externalId}?associations=transactions`.

Deposit used to fund A. The deposit template must be consulted, not assumed.
Live 1.11.0 requires `paymentTypeId`. Verified working body:

```json
{"paymentTypeId":1,"transactionDate":"14 August 2026","transactionAmount":10000,"dateFormat":"dd MMMM yyyy","locale":"en"}
```

Verified response:

```json
{"officeId":1,"clientId":1,"savingsId":1,"resourceId":1,"changes":{"paymentTypeId":1}}
```

Payment type 1 on this lab is "Money Transfer", `isSystemDefined` false.
Types 2 and 3 are system-defined loan adjustments — do not use them.
Do not hardcode `1`. `seed.py` calls `GET /v1/paymenttypes` and selects a
type with `isSystemDefined` false (lowest id if several). It fails if none
exists.

`transactionDate` is the system date. Live check: `GET /v1/configurations`
shows `enable-business-date` = False (id 44, hyphens not underscores).
`GET /v1/businessdate` therefore returns `[]`. That is the Fineract default
and this lab's normal state. Do not enable the feature — it is the
counterparty's configuration and out of scope. `seed.py` treats `[]` / no
`BUSINESS_DATE` as disabled, logs one line, and uses the system date. A
non-list or malformed entry still fails loudly.

```
POST /fineract-provider/api/v1/savingsaccounts/{accountId}/transactions?command=deposit
GET  /fineract-provider/api/v1/paymenttypes
GET  /fineract-provider/api/v1/savingsaccounts/{savingsId}/transactions/template
GET  /fineract-provider/api/v1/configurations
GET  /fineract-provider/api/v1/businessdate
```

(`SavingsAccountTransactionsApiResource` `@Path("/v1/savingsaccounts/{savingsId}/transactions")`.)

## LAB STATE

The lab accumulates state. A second `pytest -m pilot` on the same container
sees money already moved. Assertions must be deltas from a snapshot taken
at test start (`ledger_snapshot.delta()`), never absolute balances.

The case 1 negative control posted the mutated A→C 500 transfer directly to
Fineract (bypassing the adapter) and then posted a C→A 500 revert so
balances returned to 10000/0/0. Those two transfers remain on the ledger
and have no corresponding decision-chain record.

The case 2 negative control posted the identical A→B 100 body twice
directly (Fineract created two transfers) and then posted a B→A 200 revert
so balances returned to whatever they were after case 2's real success.
Those three extra rows also have no chain record. A confirmatory re-run
posted the same A→B 100 body twice again (`resourceId` 11 and 12) and
reverted B→A 200 (`resourceId` 13); three more unmatched rows.

The case 3 negative control posted agent two's A→B 200 directly after
agent one had already moved 900 (bypassing the group breaker). Fineract
created the transfer (`resourceId` 9). A B→A 200 revert restored
balances. Those two extra rows also have no chain record. A confirmatory
run after a live case 3 execution (A 7900→7000, B 2100→3000) posted the
same 200 body directly: Fineract accepted it (`resourceId` 19; A
7000→6800, B 3000→3200). Reverted B→A 200 (`resourceId` 20). An earlier
misfire of the same 200 while the test was unmarked (`resourceId` 16)
was also reverted (`resourceId` 17).

Case 4 joins this pytest session's dispatched `action_digest`s to Fineract
transfers whose `transferDescription` carries this session's `run_id`.
That bijection is both directions for this run only. It does not prove
the ledger contains nothing else — earlier runs, negative-control posts,
and any other source are out of scope by construction. The suite must
pass twice on the same container without a re-seed.

## What seed.py creates

Two clients (`pv-pilot-client-a`, `pv-pilot-client-b`) and **three** savings
accounts:

| Account | Owner | Funded | Role |
| --- | --- | --- | --- |
| A `pv-pilot-savings-a` | client A | 10000 deposit | source |
| B `pv-pilot-savings-b` | client B | empty | authorized destination |
| C `pv-pilot-savings-c` | client B | empty | mutation destination for case 1 |

The brief said two accounts. Case 1 mutates B → C between ALLOW and egress,
so C is required. That is the only intentional divergence; it is recorded
here rather than guessed later in a test.

Ids and balances are written to `seed-state.json` (gitignored). If a response
is missing an expected key, the process exits 2 with `FINERACT API SHAPE CHANGED`
and the raw body. Do not paper over that.

If `seed-state.json` is absent or malformed, pilot tests **error** (they
do not skip) with a message naming `cd pilot/fineract && python3 seed.py`.
That fixture lives in `tests/pilot/conftest.py`, not the root conftest.
See LAB STATE: never assert absolute balances.

## What this does not prove

This is an open-source core in a lab, a single instance, no production data,
no Tier-1 deployment. No regulator has reviewed it. `docker compose up`
passing is not a banking integration, not a production claim, and not
evidence that PrivateVault enforced anything — that is the later pilot tests,
each of which must query Fineract's ledger.

## REMOVAL

This pilot is deletable. When it expires or is abandoned:

```
rm -rf pilot/ tests/pilot/ docs/pilot/
# then revert, in the same commit:
#   WHAT-WE-DO-NOT-CLAIM.md  -> restore "no core banking system" line
#   usecases.yaml            -> drop the Fineract evidence entry
#   README claim table       -> drop the row
#   pyproject.toml           -> drop the 'pilot' extra and marker
#   .github/workflows        -> drop the 'pilot' job
# then: pytest  (must pass, unchanged count minus the pilot tests)
```

Before this branch merges, run that procedure on a scratch branch and confirm
the suite is green. If removal breaks anything, containment failed — fix the
containment, not the removal steps.
