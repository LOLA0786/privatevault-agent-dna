#!/usr/bin/env python3
"""Build the source-free Campfire partner ZIP under dist/.

The archive is an allowlist. It never includes runtime source, private
keys, API keys, or the internal deployment document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZipInfo

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_SOURCE = ROOT / "deploy" / "partners" / "campfire-blackbox" / "partner-pack"
SOURCE_ALLOWLIST = (
    "README.md",
    "API.yaml",
    "Campfire-PrivateVault.postman_collection.json",
    "TEST-PLAN.md",
    "LIMITATIONS.md",
    "examples/allow.json",
    "examples/review.json",
    "examples/block.json",
)
GENERATED = ("MANIFEST.json", "SHA256SUMS")
OPTIONAL_PUBLIC_BUNDLE = "trust-bundle.public.json"
ZIP_STAMP = (1980, 1, 1, 0, 0, 0)
FORBIDDEN_SUFFIXES = (".py", ".rs", ".pem", ".key", ".p12", ".db")
FORBIDDEN_SUBSTRINGS = (
    ".git",
    "agent_dna/",
    "api/server.py",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "PV_RECEIPT_SIGNING_KEY",
    "seed-state.json",
)
API_KEY_RE = re.compile(r"pv_[A-Za-z0-9_-]{8,}")


def assert_safe_member(name: str) -> str:
    text = name.replace("\\", "/")
    if (
        not text
        or text.startswith("/")
        or text.startswith("../")
        or "/../" in f"/{text}/"
    ):
        raise ValueError(f"unsafe path: {name}")
    if ".." in Path(text).parts:
        raise ValueError(f"unsafe path: {name}")
    return text


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_source_files(source: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(source.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        files.append(path)
    return files


def _scan_blob(name: str, data: bytes) -> None:
    lowered = name.lower()
    if lowered.endswith(FORBIDDEN_SUFFIXES):
        raise ValueError(f"forbidden suffix in {name}")
    text = data.decode("utf-8", errors="replace")
    haystack = f"{name}\n{text}"
    for marker in FORBIDDEN_SUBSTRINGS:
        if marker in haystack:
            raise ValueError(f"forbidden marker {marker!r} in {name}")
    if API_KEY_RE.search(haystack):
        raise ValueError(f"forbidden plaintext API key in {name}")


def _zip_info(name: str) -> ZipInfo:
    info = ZipInfo(filename=name, date_time=ZIP_STAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o644 & 0xFFFF) << 16
    info.create_system = 3
    return info


def build_partner_pack(  # noqa: C901 - allowlist/scan checklist
    *,
    source: Path,
    dest: Path,
    git_commit: str,
    build_time: str,
    version: str,
    public_trust_bundle: Path | None = None,
) -> Path:
    source = source.resolve()
    dest = dest.resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"partner-pack source missing: {source}")

    allow = set(SOURCE_ALLOWLIST)
    payloads: dict[str, bytes] = {}
    for path in _iter_source_files(source):
        if path.is_symlink() or stat.S_ISLNK(path.lstat().st_mode):
            raise ValueError(f"symlink refused: {path}")
        rel = assert_safe_member(path.relative_to(source).as_posix())
        if rel not in allow:
            raise ValueError(f"file outside allowlist: {rel}")
        payloads[rel] = path.read_bytes()

    missing = [name for name in SOURCE_ALLOWLIST if name not in payloads]
    if missing:
        raise FileNotFoundError("partner-pack missing: " + ", ".join(missing))

    if public_trust_bundle is not None:
        bundle_path = public_trust_bundle.resolve()
        if bundle_path.is_symlink():
            raise ValueError("public trust bundle must not be a symlink")
        if not bundle_path.is_file():
            raise FileNotFoundError(f"public trust bundle missing: {bundle_path}")
        payloads[OPTIONAL_PUBLIC_BUNDLE] = bundle_path.read_bytes()

    for name, data in payloads.items():
        _scan_blob(name, data)

    content_names = sorted(payloads)
    sums_lines = [f"{_sha256_bytes(payloads[name])}  {name}" for name in content_names]
    sums = ("\n".join(sums_lines) + "\n").encode("utf-8")
    manifest = {
        "product": "PrivateVault Agent DNA",
        "pack": "campfire-blackbox",
        "pack_version": "0.1",
        "product_version": version,
        "git_commit": git_commit,
        "build_time": build_time,
        "files": [
            {"path": name, "sha256": _sha256_bytes(payloads[name])}
            for name in content_names
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    payloads["SHA256SUMS"] = sums
    payloads["MANIFEST.json"] = manifest_bytes
    for name in GENERATED:
        _scan_blob(name, payloads[name])

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w") as zf:
        for name in sorted(payloads):
            zf.writestr(_zip_info(name), payloads[name])

    with zipfile.ZipFile(tmp) as zf:
        names = zf.namelist()
        expected = sorted(payloads)
        if names != expected:
            raise ValueError(f"zip namelist {names} != {expected}")
        for info in zf.infolist():
            assert_safe_member(info.filename)
            if info.filename.endswith("/"):
                continue
            data = zf.read(info.filename)
            _scan_blob(info.filename, data)
    tmp.replace(dest)
    return dest


def _git_commit() -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _product_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("could not read product version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "dist" / "campfire-blackbox-v0.1.zip",
    )
    parser.add_argument("--git-commit", default=None)
    parser.add_argument("--build-time", default=None)
    parser.add_argument("--version", default=None)
    parser.add_argument(
        "--public-trust-bundle",
        type=Path,
        default=None,
        help="Optional public trust bundle. Never discovered automatically.",
    )
    args = parser.parse_args()
    build_time = args.build_time
    if build_time is None:
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch:
            build_time = datetime.fromtimestamp(int(epoch), tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            build_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = build_partner_pack(
        source=args.source,
        dest=args.out,
        git_commit=args.git_commit or _git_commit(),
        build_time=build_time,
        version=args.version or _product_version(),
        public_trust_bundle=args.public_trust_bundle,
    )
    digest = _sha256_bytes(path.read_bytes())
    print(f"wrote {path}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
