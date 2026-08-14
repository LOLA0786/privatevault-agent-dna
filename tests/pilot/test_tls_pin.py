"""Named test behind the TLS pin claim. Not one of the four enforcement cases."""

from __future__ import annotations

import ssl
import subprocess
from http.client import HTTPSConnection
from pathlib import Path

import pytest

pytestmark = pytest.mark.pilot


def _health(ctx: ssl.SSLContext) -> int:
    conn = HTTPSConnection("localhost", 8443, context=ctx, timeout=10)
    try:
        conn.request("GET", "/fineract-provider/actuator/health")
        return conn.getresponse().status
    finally:
        conn.close()


def test_hostname_checking_is_on(tls_context: ssl.SSLContext) -> None:
    assert tls_context.check_hostname is True
    assert tls_context.verify_mode == ssl.CERT_REQUIRED


def test_pinned_cert_rejects_a_different_ca(
    tls_context: ssl.SSLContext, tmp_path: Path
) -> None:
    assert _health(tls_context) == 200

    other = tmp_path / "other-ca.pem"
    key = tmp_path / "other-ca.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(other),
            "-subj",
            "/CN=other-ca",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    wrong = ssl.create_default_context(cafile=str(other))
    wrong.check_hostname = True
    wrong.verify_mode = ssl.CERT_REQUIRED
    conn = HTTPSConnection("localhost", 8443, context=wrong, timeout=10)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            conn.request("GET", "/fineract-provider/actuator/health")
            conn.getresponse()
    finally:
        conn.close()
