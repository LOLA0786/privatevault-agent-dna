"""
Signed export manifest — closes the gap between "records are
internally consistent" (proven by verify_records.py) and "this
specific file a third party received matches what was actually
exported" (custody integrity, not proven by internal consistency
alone).

An export manifest is produced ALONGSIDE an audit export, never
embedded inside it -- the exported JSONL stays byte-identical to
what verify_records.py already consumes, unchanged. The manifest is
a separate, small, signable artifact: hash of the exported file,
timestamp, who requested the export, and (if a signer is available)
an Ed25519 signature over that manifest, using the same
SignatureEnvelope shape and verify_envelope logic as decision
records -- no second, inconsistent signature format.

A third party who later verifies:
  1. verify_records.py against the JSONL (internal consistency), AND
  2. this manifest's file_hash against the JSONL they actually
     received (custody: is this the file that was really exported),
     and the manifest's signature (was the manifest itself produced
     by the claimed operator, not forged after the fact)
...gets both properties this module exists to distinguish.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _hash_file(path: Path) -> str:
    """SHA-256 of the file's exact bytes -- must match how a
    recipient would hash the file they received, byte for byte."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ExportManifest:
    manifest_id: str
    exported_file_hash: str  # SHA-256 of the exported JSONL's bytes
    exported_at: float
    requested_by: str | None  # e.g. API key name, or None if not tracked
    record_count: int
    signature: dict[str, Any] | None = None  # SignatureEnvelope.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "exported_file_hash": self.exported_file_hash,
            "exported_at": self.exported_at,
            "requested_by": self.requested_by,
            "record_count": self.record_count,
            "signature": self.signature,
        }

    def _content_hash(self) -> str:
        """Hash of the manifest's own content (excluding signature) --
        this is what gets signed, same pattern as a DecisionRecord's
        record_hash."""
        content = json.dumps(
            {k: v for k, v in self.to_dict().items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_against_file(self, path: Path) -> bool:
        """The core custody check: does this manifest's recorded hash
        match the actual bytes of the file a recipient has in hand?
        A mismatch means the file was altered after export, or this
        manifest doesn't belong to this file at all."""
        return _hash_file(Path(path)) == self.exported_file_hash


def create_export_manifest(
    exported_path: Path,
    record_count: int,
    requested_by: str | None = None,
    signer=None,  # optional ReceiptSigner -- signs the manifest, not the export
) -> ExportManifest:
    """Call this immediately after export_jsonl produces the file.
    The manifest binds to the file's actual bytes at the moment of
    creation -- if the file changes even slightly afterward, the
    hash will no longer match and verify_against_file will catch it."""
    file_hash = _hash_file(Path(exported_path))

    manifest = ExportManifest(
        manifest_id=f"export-{uuid.uuid4()}",
        exported_file_hash=file_hash,
        exported_at=time.time(),
        requested_by=requested_by,
        record_count=record_count,
    )

    if signer is not None:
        manifest_hash = manifest._content_hash()
        envelope = signer.sign_hash(manifest_hash)
        manifest.signature = envelope.to_dict()

    return manifest


def verify_export_manifest(
    manifest_dict: dict[str, Any],
    exported_path: Path,
    *,
    trusted_keys: Collection[str] | None = None,
) -> dict[str, Any]:
    """Standalone verification a third party runs: does the manifest's
    recorded hash match the file they actually have, and (if signed)
    does the signature validate against the manifest's own content
    hash. Returns a structured result -- never raises, always reports
    what it found."""
    from .signer import verify_trusted_envelope

    manifest = ExportManifest(
        manifest_id=manifest_dict["manifest_id"],
        exported_file_hash=manifest_dict["exported_file_hash"],
        exported_at=manifest_dict["exported_at"],
        requested_by=manifest_dict.get("requested_by"),
        record_count=manifest_dict["record_count"],
        signature=manifest_dict.get("signature"),
    )

    file_matches = manifest.verify_against_file(exported_path)

    signature_valid = None
    if manifest.signature is not None:
        expected_hash = manifest._content_hash()
        signature_valid = verify_trusted_envelope(
            manifest.signature,
            expected_hash,
            trusted_keys=trusted_keys,
        )

    return {
        "file_hash_matches": file_matches,
        "signature_valid": signature_valid,
        "content_integrity_verified": file_matches,
        "custody_verified": file_matches and signature_valid is True,
    }
