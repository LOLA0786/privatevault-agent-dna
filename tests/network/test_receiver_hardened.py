"""The receiver kit is hardened by default (external review, 19 October 2026).

The review found that the kit served plain HTTP unless started a special
way, that its gate constructor never attached the revocation list, and that
nothing made presenters required. Each relaxation is now an explicit flag.

Claims -> tests:
  - No TLS settings and no PV_RECEIVER_ALLOW_PLAINTEXT=1: the gate does not
    start; plaintext plus TLS settings is a contradiction; uvicorn's app
    entry point refuses mTLS settings it cannot honour
    -> test_plaintext_needs_an_explicit_flag, test_app_entry_point_*
  - With mTLS a presenter is required unless explicitly turned off
    -> test_mtls_requires_presenters_by_default
  - No PV_REVOCATION_URL and no PV_RECEIVER_ALLOW_NO_REVOCATION=1: the gate
    does not start; http needs its own flag; the API key file is required
    -> test_revocation_source_is_required, test_revocation_settings_are_checked[*]
  - build_gate attaches the list: before a signed list is installed every
    permit is refused (503) and nothing reaches the upstream
    -> test_gate_refuses_everything_until_a_list_is_installed
  - The refresher installs verified lists, so a revoked permit is refused,
    and a list it cannot fetch or verify changes nothing; once the installed
    list expires the gate refuses again
    -> test_revoked_permit_is_refused_after_refresh,
       test_unreachable_api_ends_in_refusals_not_admissions,
       test_bad_key_or_forged_list_is_not_installed,
       test_background_refresh_picks_up_a_revocation
  - The image runs serve.py, and the entrypoint hands the TLS key and the
    revocation API key to the gate user like the receipt key
    -> test_image_serves_mtls_by_default, test_entrypoint_hands_over_every_secret
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from nacl.signing import SigningKey

from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.revocation_list import build_revocation_list
from network.receiver_kit import config, send_test, upstream
from network.receiver_kit.revocations import RevocationRefresher, start_refresher
from tests.network.test_receiver_kit import KIT, ORG, _env, _issuer

API_KEY = "pv_test-audit-key-not-a-secret"


class _Store:
    def __init__(self) -> None:
        self.revoked: list[str] = []

    def revocation_rows(self):
        return [("authorization", r) for r in self.revoked], {}


class _ListServer:
    """Stands in for GET /v1/revocations on the PrivateVault API."""

    def __init__(self, signer: SigningKey, *, validity_s: int = 30) -> None:
        self.store = _Store()
        self.signer = signer
        self.validity = timedelta(seconds=validity_s)
        self.override: dict[str, Any] | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.headers.get("X-API-Key") != API_KEY:
                    self.send_response(401)
                    self.end_headers()
                    return
                doc = outer.override or build_revocation_list(
                    outer.store,
                    organisation_id=ORG,
                    signing_key=outer.signer,
                    signer_key_id="ea-signer",
                    validity=outer.validity,
                )
                body = json.dumps(doc).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/revocations"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Gate:
    def __init__(self, tmp_path: Path, **over: str) -> None:
        self.issuer_key = SigningKey.generate()
        self.lists = _ListServer(
            self.issuer_key, validity_s=int(over.pop("validity", "30"))
        )
        key_file = tmp_path / "revocation-api.key"
        key_file.write_text(over.pop("api_key", API_KEY) + "\n")
        self.upstream = upstream.start()
        self.env = _env(
            tmp_path,
            self.issuer_key,
            SigningKey.generate(),
            PV_UPSTREAM=f"http://127.0.0.1:{self.upstream.port}",
            PV_RECEIVER_ALLOW_NO_REVOCATION="",
            PV_REVOCATION_URL=self.lists.url,
            PV_ALLOW_HTTP_REVOCATION="1",
            PV_REVOCATION_API_KEY_FILE=str(key_file),
            **over,
        )
        self.settings = config.settings_from_env(self.env)
        self.gate = config.build_gate(self.settings)
        from agent_dna.receiver.asgi import ReceiverGateProxy

        self.app = ReceiverGateProxy(
            self.gate, self.settings.upstream, allow_http_upstream=True
        )
        self.issuer = _issuer(self.env, self.issuer_key)
        self.refresher = RevocationRefresher(
            self.gate.revocations,
            url=self.settings.revocation_url,
            api_key_file=self.settings.revocation_api_key_file,
            interval_seconds=self.settings.revocation_refresh_seconds,
        )

    def send(self, permit: Mapping[str, Any], wire: bytes) -> tuple[int, bytes]:
        async def go() -> tuple[int, bytes]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.app), base_url="http://gate"
            ) as client:
                r = await client.post(
                    send_test.PATH,
                    headers={
                        "Content-Type": "application/json",
                        PERMIT_HEADER: encode_permit_header(dict(permit)),
                    },
                    content=wire,
                )
                return r.status_code, r.content

        return anyio.run(go)

    def mint(self) -> tuple[dict[str, Any], bytes]:
        return send_test.mint_permit(self.issuer, send_test.PARAMETERS)

    def close(self) -> None:
        self.refresher.stop()
        self.lists.stop()


@pytest.fixture()
def gate(tmp_path):
    g = _Gate(tmp_path)
    yield g
    g.close()


def _hardened(tmp_path, **over):
    """Base env with the demo relaxations cleared."""
    return _env(
        tmp_path,
        SigningKey.generate(),
        SigningKey.generate(),
        PV_RECEIVER_ALLOW_PLAINTEXT="",
        PV_RECEIVER_ALLOW_NO_REVOCATION="",
        **over,
    )


def _tls_files(tmp_path):
    cert = tmp_path / "tls.pem"
    cert.write_text("x")
    return {
        "PV_RECEIVER_TLS_CERT": str(cert),
        "PV_RECEIVER_TLS_KEY": str(cert),
        "PV_RECEIVER_CLIENT_CA": str(cert),
    }


def _revocation(tmp_path):
    key = tmp_path / "api.key"
    key.write_text(API_KEY)
    return {
        "PV_REVOCATION_URL": "https://pv-api.internal/v1/revocations",
        "PV_REVOCATION_API_KEY_FILE": str(key),
    }


# ---- configuration ---------------------------------------------------------------


def test_plaintext_needs_an_explicit_flag(tmp_path):
    env = _hardened(tmp_path, **_revocation(tmp_path))
    with pytest.raises(config.ConfigError, match="mutual TLS only"):
        config.settings_from_env(env)
    settings = config.settings_from_env({**env, **_tls_files(tmp_path)})
    assert settings.mtls and not settings.allow_plaintext
    with pytest.raises(config.ConfigError, match="contradicts the TLS"):
        config.settings_from_env(
            {**env, **_tls_files(tmp_path), "PV_RECEIVER_ALLOW_PLAINTEXT": "1"}
        )
    demo = config.settings_from_env({**env, "PV_RECEIVER_ALLOW_PLAINTEXT": "1"})
    assert not demo.mtls and not demo.require_presenter
    assert "PLAINTEXT" in config.describe(demo, config.build_gate(demo))


def test_mtls_requires_presenters_by_default(tmp_path):
    env = _hardened(tmp_path, **_revocation(tmp_path), **_tls_files(tmp_path))
    settings = config.settings_from_env(env)
    assert settings.require_presenter
    assert config.build_gate(settings).require_presenter is True
    relaxed = config.settings_from_env({**env, "PV_RECEIVER_REQUIRE_PRESENTER": "0"})
    assert not relaxed.require_presenter


def test_revocation_source_is_required(tmp_path):
    env = _hardened(tmp_path, **_tls_files(tmp_path))
    with pytest.raises(config.ConfigError, match="PV_REVOCATION_URL is required"):
        config.settings_from_env(env)
    off = config.settings_from_env({**env, "PV_RECEIVER_ALLOW_NO_REVOCATION": "1"})
    gate = config.build_gate(off)
    assert gate.revocations is None
    assert "revoked permits are admitted until they expire" in config.describe(
        off, gate
    )
    on = config.settings_from_env({**env, **_revocation(tmp_path)})
    gate = config.build_gate(on)
    assert gate.revocations is not None
    text = config.describe(on, gate)
    assert "refuses all permits while stale" in text
    assert API_KEY not in text
    assert "run one receiver host" in text


@pytest.mark.parametrize(
    "over, match",
    [
        ({"PV_RECEIVER_ALLOW_NO_REVOCATION": "1"}, "contradicts PV_REVOCATION_URL"),
        ({"PV_REVOCATION_URL": "http://pv-api/v1/revocations"}, "in clear"),
        ({"PV_REVOCATION_URL": "ftp://pv-api/x"}, "https://"),
        ({"PV_REVOCATION_API_KEY_FILE": ""}, "PV_REVOCATION_API_KEY_FILE is required"),
        ({"PV_REVOCATION_API_KEY_FILE": "/nonexistent/key"}, "is not a file"),
        ({"PV_REVOCATION_CA_FILE": "/nonexistent/ca.pem"}, "is not a file"),
        ({"PV_REVOCATION_REFRESH_SECONDS": "0"}, ">= 1"),
        ({"PV_REVOCATION_REFRESH_SECONDS": "301"}, "<= 300"),
    ],
    ids=[
        "contradiction",
        "http",
        "scheme",
        "no-key",
        "missing-key",
        "missing-ca",
        "too-fast",
        "too-slow",
    ],
)
def test_revocation_settings_are_checked(tmp_path, over, match):
    env = {**_hardened(tmp_path, **_tls_files(tmp_path)), **_revocation(tmp_path)}
    with pytest.raises(config.ConfigError, match=match):
        config.settings_from_env({**env, **over})


def test_app_entry_point_refuses_mtls_settings(tmp_path):
    env = {
        **_hardened(tmp_path, **_tls_files(tmp_path)),
        **_revocation(tmp_path),
    }
    clean = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    result = subprocess.run(
        [sys.executable, "-c", "import network.receiver_kit.app"],
        env={**clean, **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode != 0
    assert "uvicorn cannot require client certificates" in result.stderr


# ---- the gate and its list -------------------------------------------------------


def test_gate_refuses_everything_until_a_list_is_installed(gate):
    permit, wire = gate.mint()
    status, body = gate.send(permit, wire)
    assert status == 503 and b"RECEIVER_REVOCATION_LIST_STALE" in body
    assert gate.upstream.seen() == []
    assert gate.refresher.refresh_once()
    permit, wire = gate.mint()
    status, body = gate.send(permit, wire)
    assert status == 200, body
    assert len(gate.upstream.seen()) == 1


def test_revoked_permit_is_refused_after_refresh(gate):
    permit, wire = gate.mint()
    gate.lists.store.revoked.append(permit["execution_authorization_id"])
    assert gate.refresher.refresh_once()
    status, body = gate.send(permit, wire)
    assert status == 403 and b"RECEIVER_PERMIT_REVOKED" in body
    assert gate.upstream.seen() == []


def test_unreachable_api_ends_in_refusals_not_admissions(tmp_path):
    g = _Gate(tmp_path, validity="1")
    try:
        assert g.refresher.refresh_once()
        permit, wire = g.mint()
        g.lists.stop()  # the API becomes unreachable
        assert not g.refresher.refresh_once()
        assert g.refresher.last_error is not None
        time.sleep(2.1)  # past next_update
        status, body = g.send(permit, wire)
        assert status == 503 and b"RECEIVER_REVOCATION_LIST_STALE" in body
        assert g.upstream.seen() == []
    finally:
        g.refresher.stop()


def test_bad_key_or_forged_list_is_not_installed(tmp_path, capsys):
    g = _Gate(tmp_path, api_key="wrong-key")
    try:
        assert not g.refresher.refresh_once()
        assert "HTTPError" in (g.refresher.last_error or "")
        assert g.gate.revocations.current is None
        assert "wrong-key" not in capsys.readouterr().err
        # a list signed by another key is refused even with the right API key
        (tmp_path / "revocation-api.key").write_text(API_KEY)
        g.lists.override = build_revocation_list(
            _Store(),
            organisation_id=ORG,
            signing_key=SigningKey.generate(),
            signer_key_id="ea-signer",
        )
        assert not g.refresher.refresh_once()
        assert "signature" in (g.refresher.last_error or "")
        assert g.gate.revocations.current is None
    finally:
        g.close()


def test_background_refresh_picks_up_a_revocation(tmp_path):
    g = _Gate(tmp_path, PV_REVOCATION_REFRESH_SECONDS="1")
    try:
        refresher = start_refresher(g.gate, g.settings)
        assert refresher is not None and g.gate.revocations.current is not None
        permit, wire = g.mint()
        g.lists.store.revoked.append(permit["execution_authorization_id"])
        deadline = time.monotonic() + 10
        while (
            permit["execution_authorization_id"]
            not in (g.gate.revocations.current["revoked_authorizations"])
        ):
            assert time.monotonic() < deadline, "background refresh did not run"
            time.sleep(0.1)
        status, body = g.send(permit, wire)
        assert status == 403 and b"RECEIVER_PERMIT_REVOKED" in body
        refresher.stop()
    finally:
        g.close()


# ---- the image ---------------------------------------------------------------------


def test_image_serves_mtls_by_default():
    dockerfile = (KIT / "Dockerfile").read_text()
    assert 'CMD ["python", "-m", "network.receiver_kit.serve"]' in dockerfile
    assert "uvicorn" not in dockerfile.split("CMD", 1)[1]
    import yaml

    gate = yaml.safe_load((KIT / "docker-compose.yml").read_text())["services"]["gate"]
    # the local demo opts out explicitly, and says so
    assert gate["environment"]["PV_RECEIVER_ALLOW_PLAINTEXT"] == "1"
    assert gate["environment"]["PV_RECEIVER_ALLOW_NO_REVOCATION"] == "1"
    assert "LOCAL DEMO ONLY" in (KIT / "docker-compose.yml").read_text()


@pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("setpriv") is None,
    reason="runs the entrypoint as root, as the container does",
)
def test_entrypoint_hands_over_every_secret(tmp_path):
    """Run entrypoint.sh as root (as in the container): each secret becomes a
    0400 copy owned by the gate uid in /run/pv; originals are untouched."""
    secrets = {}
    for var, name in (
        ("PV_RECEIPT_KEY_FILE", "receiver.key"),
        ("PV_RECEIVER_TLS_KEY", "tls.key"),
        ("PV_REVOCATION_API_KEY_FILE", "revocation-api.key"),
    ):
        path = tmp_path / f"host-{name}"
        path.write_text("secret\n")
        path.chmod(0o600)
        try:
            os.chown(path, 4242, 4242)  # the host user's uid, not the gate's
        except OSError as exc:  # e.g. a user namespace without that uid
            pytest.skip(f"this host cannot give a file to uid 4242: {exc}")
        secrets[var] = (path, name)
    uid = 20000 + os.getpid() % 10000
    env = {
        "PATH": os.environ["PATH"],
        "PV_GATE_UID": str(uid),
        "PV_GATE_GID": str(uid),
        **{var: str(path) for var, (path, _) in secrets.items()},
    }
    script = "id -u; " + "; ".join(
        f'echo "${var}"; stat -c "%u:%a" "${var}"; cat "${var}"' for var in secrets
    )
    try:
        run = subprocess.run(
            ["sh", str(KIT / "entrypoint.sh"), "sh", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert run.returncode == 0, run.stderr
        lines = run.stdout.split("\n")
        assert lines[0] == str(uid)
        for i, (_var, (path, name)) in enumerate(secrets.items()):
            got_path, owner_mode, content = lines[1 + 3 * i : 4 + 3 * i]
            assert got_path == f"/run/pv/{name}"
            assert owner_mode == f"{uid}:400"
            assert content == "secret"
            assert path.stat().st_uid == 4242 and path.stat().st_mode & 0o777 == 0o600
    finally:
        shutil.rmtree("/run/pv", ignore_errors=True)
