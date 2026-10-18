"""Backups of the PrivateVault ledgers, and restores that prove themselves.

    python -m agent_dna.backup backup  --database-url URL | --sqlite PATH  --out DIR
                                       [--signing-key FILE|awskms:..|gcpkms:..]
    python -m agent_dna.backup verify  DIR [--public-key BASE64]
    python -m agent_dna.backup restore DIR --database-url URL | --sqlite PATH
                                       [--public-key BASE64]

A backup directory holds the dump (``pg_dump --format=custom``, or a SQLite
online-backup copy) and ``manifest.json``: the dump's SHA-256 and size, and a
fingerprint of every table at the time of the dump (row count and a SHA-256
over every row in a fixed order), plus the latest decision-record hash per
agent. With a signing key (local seed or KMS, ADR 0023) the manifest is
signed, so a backup set cannot be swapped or edited unnoticed.

``restore`` refuses a target that already holds tables, restores, and then
proves the result: every table's fingerprint must equal the manifest's, and
every decision chain must verify. A restore that does not match is reported
as failed even though the data was loaded.

PostgreSQL needs ``pg_dump``/``pg_restore`` of at least the server's major
version on PATH. Point-in-time recovery (WAL archiving, managed-database
snapshots) is the database platform's job; this is the logical, verifiable
copy you can restore anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BACKUP_SPEC = "pv-ledger-backup/0.1"
MANIFEST = "manifest.json"
PG_DUMP_FILE = "ledger.pgdump"
SQLITE_FILE = "ledger.sqlite3"


class BackupError(RuntimeError):
    """The backup or restore could not be completed or proven."""


# ---- fingerprints ----------------------------------------------------------------


def _value(v: Any) -> Any:
    if isinstance(v, bytes | bytearray | memoryview):
        return {"bytes": bytes(v).hex()}
    if isinstance(v, int | str) or v is None:
        return v
    if isinstance(v, float):
        return repr(v)
    return str(v)


def _table_digest(rows: Iterable[tuple[Any, ...]]) -> tuple[int, str]:
    h = hashlib.sha256()
    count = 0
    for row in rows:
        h.update(json.dumps([_value(v) for v in row], separators=(",", ":")).encode())
        h.update(b"\n")
        count += 1
    return count, "sha256:" + h.hexdigest()


def _pg_connect(url: str) -> Any:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - the postgres extra is missing
        raise BackupError("PostgreSQL backups need the postgres extra") from exc
    return psycopg.connect(url)


def _pg_tables(conn: Any) -> list[str]:
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1"
    ).fetchall()
    return [r[0] for r in rows]


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def fingerprint_postgres(url: str) -> dict[str, Any]:
    with _pg_connect(url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        return _fingerprint_postgres_conn(conn)


def _fingerprint_postgres_conn(conn: Any) -> dict[str, Any]:
    """Fingerprint inside the connection's current (repeatable-read) snapshot."""
    tables: dict[str, Any] = {}
    for name in _pg_tables(conn):
        ncols = len(
            conn.execute(f"SELECT * FROM {_quote(name)} LIMIT 0").description or []
        )
        order = ", ".join(str(i) for i in range(1, ncols + 1))
        cur = conn.execute(f"SELECT * FROM {_quote(name)} ORDER BY {order}")
        count, digest = _table_digest(cur)
        tables[name] = {"rows": count, "digest": digest}
    sequences = {
        r[0]: int(r[1] or 0)
        for r in conn.execute(
            "SELECT sequencename, last_value FROM pg_sequences "
            "WHERE schemaname = 'public' ORDER BY 1"
        ).fetchall()
    }
    heads = _heads(conn.execute, "records" in tables)
    server = conn.execute("SHOW server_version").fetchone()[0]
    return {
        "tables": tables,
        "sequences": sequences,
        "chain_heads": heads,
        "server": server,
    }


def fingerprint_sqlite(path: str | Path) -> dict[str, Any]:
    uri = f"file:{Path(path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY 1"
            )
        ]
        tables: dict[str, Any] = {}
        for name in names:
            ncols = len(
                conn.execute(f"SELECT * FROM {_quote(name)} LIMIT 0").description
            )
            order = ", ".join(str(i) for i in range(1, ncols + 1))
            count, digest = _table_digest(
                conn.execute(f"SELECT * FROM {_quote(name)} ORDER BY {order}")
            )
            tables[name] = {"rows": count, "digest": digest}
        heads = _heads(conn.execute, "records" in tables)
    finally:
        conn.close()
    return {
        "tables": tables,
        "sequences": {},
        "chain_heads": heads,
        "server": "sqlite " + sqlite3.sqlite_version,
    }


def _heads(execute: Any, has_records: bool) -> dict[str, str]:
    """Latest decision-record hash per agent: what an auditor compares."""
    if not has_records:
        return {}
    rows = execute(
        "SELECT agent_id, record_hash FROM records r WHERE kind = 'decision' AND "
        "seq = (SELECT MAX(seq) FROM records x WHERE x.agent_id = r.agent_id "
        "AND x.kind = 'decision') ORDER BY agent_id"
    ).fetchall()
    return {r[0]: r[1] for r in rows}


# ---- manifest --------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _redact(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or "?"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path}"


def _sign_manifest(manifest: dict[str, Any], key_ref: str | None) -> dict[str, Any]:
    if not key_ref:
        return manifest
    from agent_dna.authority_v01 import encode_public_key, sign_document
    from agent_dna.key_custody import signer_from_seed_file

    signer = signer_from_seed_file(key_ref)
    manifest = dict(manifest, signer_public_key=encode_public_key(signer))
    return sign_document(manifest, signer, signature_field="signature")


def verify_backup(
    directory: str | Path, public_key: str | None = None
) -> dict[str, Any]:
    """Check the dump against the manifest, and the manifest's signature."""
    directory = Path(directory)
    try:
        manifest = json.loads((directory / MANIFEST).read_text())
    except (OSError, ValueError) as exc:
        raise BackupError(f"no readable {MANIFEST} in {directory}") from exc
    if manifest.get("spec") != BACKUP_SPEC:
        raise BackupError("not a PrivateVault ledger backup")
    dump = directory / manifest["dump"]["file"]
    if not dump.is_file() or _sha256_file(dump) != manifest["dump"]["sha256"]:
        raise BackupError(
            "dump does not match the manifest (changed, truncated or missing)"
        )
    if "signature" in manifest:
        from agent_dna.authority_v01 import verify_document_signature

        key = public_key or manifest.get("signer_public_key")
        if public_key and manifest.get("signer_public_key") != public_key:
            raise BackupError("manifest was signed by a different key")
        try:
            ok = verify_document_signature(
                manifest, signature_field="signature", public_key=key
            )
        except Exception as exc:
            raise BackupError("manifest signature does not verify") from exc
        if not ok:
            raise BackupError("manifest signature does not verify")
    elif public_key:
        raise BackupError("manifest is unsigned but a public key was required")
    return manifest


# ---- backup ----------------------------------------------------------------------


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise BackupError(f"{name} not found on PATH (install the PostgreSQL client)")
    return found


def backup_postgres(
    url: str, out: str | Path, *, signing_key: str | None = None
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    dump = out / PG_DUMP_FILE
    # One snapshot for both: the fingerprint is computed inside an exported
    # repeatable-read snapshot and pg_dump dumps that same snapshot, so the
    # manifest describes exactly what was dumped while writes carry on.
    with _pg_connect(url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        snapshot = conn.execute("SELECT pg_export_snapshot()").fetchone()[0]
        fingerprint = _fingerprint_postgres_conn(conn)
        result = subprocess.run(
            [_tool("pg_dump"), "--format=custom", "--no-owner", "--no-privileges",
             f"--snapshot={snapshot}", "--file", str(dump), url],
            capture_output=True, text=True,
        )  # fmt: skip
    if result.returncode != 0:
        shutil.rmtree(out, ignore_errors=True)
        raise BackupError(f"pg_dump failed: {result.stderr.strip()[:500]}")
    version = subprocess.run(
        [_tool("pg_dump"), "--version"], capture_output=True, text=True
    )
    return _finish(
        out, dump, fingerprint, signing_key,
        source={"kind": "postgresql", "database": _redact(url), "tool": version.stdout.strip()},
    )  # fmt: skip


def backup_sqlite(
    path: str | Path, out: str | Path, *, signing_key: str | None = None
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    dump = out / SQLITE_FILE
    src = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
    dst = sqlite3.connect(dump)
    try:
        src.backup(dst)  # consistent online copy, even with writers
    finally:
        dst.close()
        src.close()
    return _finish(
        out, dump, fingerprint_sqlite(dump), signing_key,
        source={"kind": "sqlite", "database": str(Path(path).name), "tool": "sqlite3 backup API"},
    )  # fmt: skip


def _finish(
    out: Path,
    dump: Path,
    fingerprint: Mapping[str, Any],
    signing_key: str | None,
    *,
    source: dict[str, str],
) -> dict[str, Any]:
    os.chmod(dump, 0o600)
    manifest = {
        "spec": BACKUP_SPEC,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "dump": {
            "file": dump.name,
            "sha256": _sha256_file(dump),
            "bytes": dump.stat().st_size,
        },
        "fingerprint": dict(fingerprint),
    }
    manifest = _sign_manifest(manifest, signing_key)
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


# ---- restore ---------------------------------------------------------------------


def _verify_chains_postgres(url: str) -> dict[str, bool]:
    from agent_dna.pg_store import PostgresDecisionStore

    store = PostgresDecisionStore(url, max_size=2)
    try:
        return dict(store.load_graph().verify_all())
    finally:
        store.close()


def _verify_chains_sqlite(path: Path) -> dict[str, bool]:
    from agent_dna.sqlite_store import SQLiteDecisionStore

    if "records" not in fingerprint_sqlite(path)["tables"]:
        return {}
    return dict(SQLiteDecisionStore(path).load_graph().verify_all())


def _compare(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> list[str]:
    problems = []
    for name, want in expected["tables"].items():
        got = actual["tables"].get(name)
        if got != want:
            problems.append(f"table {name}: expected {want}, restored {got}")
    for name in set(actual["tables"]) - set(expected["tables"]):
        problems.append(f"table {name}: not in the backup")
    # Sequences are not transactional: pg_dump may read one a moment after
    # the snapshot. What matters is that new rows cannot reuse old ids.
    for name, value in expected.get("sequences", {}).items():
        if actual.get("sequences", {}).get(name, -1) < value:
            problems.append(f"sequence {name}: restored behind {value}")
    if expected.get("chain_heads") != actual.get("chain_heads"):
        problems.append("decision chain heads differ")
    return problems


def restore(
    directory: str | Path,
    *,
    database_url: str | None = None,
    sqlite_path: str | Path | None = None,
    public_key: str | None = None,
) -> dict[str, Any]:
    """Restore into an empty target and prove it equals the backup."""
    directory = Path(directory)
    manifest = verify_backup(directory, public_key)
    dump = directory / manifest["dump"]["file"]
    kind = manifest["source"]["kind"]
    if kind == "postgresql":
        if not database_url:
            raise BackupError("a PostgreSQL backup restores into --database-url")
        with _pg_connect(database_url) as conn:
            if _pg_tables(conn):
                raise BackupError(
                    "restore target is not empty; restore into a new database"
                )
        result = subprocess.run(
            [_tool("pg_restore"), "--no-owner", "--no-privileges", "--exit-on-error",
             "--single-transaction", "--dbname", database_url, str(dump)],
            capture_output=True, text=True,
        )  # fmt: skip
        if result.returncode != 0:
            raise BackupError(f"pg_restore failed: {result.stderr.strip()[:500]}")
        actual = fingerprint_postgres(database_url)
        chains = (
            _verify_chains_postgres(database_url)
            if "records" in actual["tables"]
            else {}
        )
    elif kind == "sqlite":
        if not sqlite_path:
            raise BackupError("a SQLite backup restores into --sqlite")
        target = Path(sqlite_path)
        if target.exists():
            raise BackupError("restore target exists; restore into a new file")
        shutil.copyfile(dump, target)
        os.chmod(target, 0o600)
        actual = fingerprint_sqlite(target)
        chains = _verify_chains_sqlite(target)
    else:
        raise BackupError(f"unknown backup kind {kind!r}")
    problems = _compare(manifest["fingerprint"], actual)
    broken = sorted(agent for agent, ok in chains.items() if not ok)
    if broken:
        problems.append(f"decision chains do not verify: {broken}")
    report = {
        "restored": True,
        "verified": not problems,
        "tables": len(actual["tables"]),
        "rows": sum(t["rows"] for t in actual["tables"].values()),
        "chains_verified": len(chains),
        "problems": problems,
    }
    if problems:
        raise BackupError(
            "restored data does not match the backup: " + "; ".join(problems)
        )
    return report


# ---- CLI -------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_dna.backup", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup", help="dump the ledger and write a manifest")
    src = b.add_mutually_exclusive_group(required=True)
    src.add_argument("--database-url")
    src.add_argument("--sqlite")
    b.add_argument("--out", required=True, help="new directory for this backup")
    b.add_argument("--signing-key", help="seed file or awskms:/gcpkms: reference")
    v = sub.add_parser("verify", help="check a backup's dump and manifest")
    v.add_argument("directory")
    v.add_argument(
        "--public-key", help="base64 Ed25519 key the manifest must be signed by"
    )
    r = sub.add_parser("restore", help="restore into an empty target and prove it")
    r.add_argument("directory")
    dst = r.add_mutually_exclusive_group(required=True)
    dst.add_argument("--database-url")
    dst.add_argument("--sqlite")
    r.add_argument("--public-key")
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            if args.database_url:
                out = backup_postgres(
                    args.database_url, args.out, signing_key=args.signing_key
                )
            else:
                out = backup_sqlite(args.sqlite, args.out, signing_key=args.signing_key)
            summary = {
                "ok": True,
                "dump": out["dump"],
                "tables": len(out["fingerprint"]["tables"]),
                "signed": "signature" in out,
            }
        elif args.command == "verify":
            manifest = verify_backup(args.directory, args.public_key)
            summary = {
                "ok": True,
                "created_at": manifest["created_at"],
                "signed": "signature" in manifest,
            }
        else:
            summary = {"ok": True, **restore(
                args.directory, database_url=args.database_url,
                sqlite_path=args.sqlite, public_key=args.public_key,
            )}  # fmt: skip
    except BackupError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
