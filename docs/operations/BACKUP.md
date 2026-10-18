# Backing up and restoring the ledgers

The ledgers are the evidence: decision records and their signatures,
permit mints and single-use claims, suspensions and revocations, grant
spend, lineage, the circuit breaker and receiver receipts. Losing them loses
the audit trail; restoring them wrongly is worse, because a ledger that
looks complete but is not would still be trusted. So a backup here comes
with the means to prove its restore.

## Take a backup

```sh
# PostgreSQL (PV_DATABASE_URL); pg_dump of the server's major version on PATH
python -m agent_dna.backup backup --database-url "$PV_DATABASE_URL" \
    --out /backups/pv-$(date -u +%Y%m%dT%H%M%SZ) \
    --signing-key awskms:arn:aws:kms:REGION:ACCOUNT:key/BACKUP_KEY   # or a seed file

# SQLite (single instance, and the receiver kit's ledger)
python -m agent_dna.backup backup --sqlite data/privatevault.db --out /backups/pv-...
```

The directory holds the dump and `manifest.json`: the dump's SHA-256, and a
fingerprint of every table (row count and a SHA-256 over every row) plus the
latest decision hash per agent. On PostgreSQL the fingerprint and the dump
come from one exported snapshot, so a backup taken while agents keep
deciding is exact. With `--signing-key` the manifest is signed (local seed
or KMS, ADR 0023); use a key that is not one of the runtime's signing keys.

Store backups outside the database's failure domain (another account or
region), encrypted at rest by the storage (for example S3 with SSE-KMS and
Object Lock). The dump contains everything the ledgers contain, including
action parameters.

## Check a backup

```sh
python -m agent_dna.backup verify /backups/pv-... --public-key BASE64_BACKUP_KEY
```

Refuses a changed or truncated dump, an edited manifest, a manifest signed
by another key, or an unsigned manifest when a key is required.

## Restore, and prove it

```sh
createdb pv_restored
python -m agent_dna.backup restore /backups/pv-... \
    --database-url postgresql://.../pv_restored --public-key BASE64_BACKUP_KEY
```

Restores only into an empty database (or a new SQLite file), then compares
every table with the manifest and re-verifies every decision chain. If
anything differs it reports failure, even though the data was loaded. Point
`PV_DATABASE_URL` at the restored database only after it reports
`"verified": true`.

Run this as a drill on a schedule, not only in an emergency: a backup that
has never been restored is a hope. CI restores a live-written backup on
every commit (`tests/test_backup.py`).

## What this is not

- Point-in-time recovery. Use the database platform for that (WAL archiving,
  or a managed database's automated backups); this is the logical copy you
  can verify and restore anywhere, and the one an auditor can check.
- A guard against an operator who controls both the database and the backup
  signing key.
