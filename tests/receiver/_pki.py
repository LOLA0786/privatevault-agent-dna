"""A throwaway PKI for mTLS tests: one CA, server and client leaves (openssl)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest


def _openssl(*args: str) -> None:
    try:
        subprocess.run(["openssl", *args], check=True, capture_output=True, text=True)
    except FileNotFoundError:  # pragma: no cover - CI images ship openssl
        pytest.skip("openssl is required for mTLS tests")


@dataclass(frozen=True)
class Leaf:
    cert: Path
    key: Path


class Pki:
    def __init__(self, directory: Path, name: str = "ca") -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert = directory / f"{name}.pem"
        self.ca_key = directory / f"{name}.key"
        _openssl(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-sha256", "-days", "2", "-nodes", "-subj", f"/CN=PV test {name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(self.ca_key), "-out", str(self.ca_cert),
        )  # fmt: skip

    def leaf(self, name: str, *, server: bool = False, key: Path | None = None) -> Leaf:
        """Issue a leaf. ``key`` re-uses an existing key (same presenter)."""
        out = self.dir / f"{name}.pem"
        keyfile = key or self.dir / f"{name}.key"
        if key is None:
            _openssl(
                "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-out", str(keyfile),
            )  # fmt: skip
        csr = self.dir / f"{name}.csr"
        _openssl(
            "req", "-new", "-key", str(keyfile), "-subj", f"/CN={name}", "-out", str(csr)
        )  # fmt: skip
        ext = self.dir / f"{name}.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            + (
                "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
                if server
                else "extendedKeyUsage=clientAuth\n"
            )
        )
        _openssl(
            "x509", "-req", "-in", str(csr), "-CA", str(self.ca_cert),
            "-CAkey", str(self.ca_key), "-CAcreateserial", "-days", "1", "-sha256",
            "-extfile", str(ext), "-out", str(out),
        )  # fmt: skip
        return Leaf(out, keyfile)
