"""Audit downloads are private while active and removed after delivery."""

import json
import os
import stat
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.signer import generate_keypair


def _client(tmp_path, monkeypatch):
    keys = generate_keypair()

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "audit-export.db"))
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", keys["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", keys["public_key"])
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)

    import importlib

    import api.server as server

    importlib.reload(server)
    return server, TestClient(server.app)


def _create_record(client):
    response = client.post(
        "/v1/decide",
        json={
            "agent_id": "audit-export-agent",
            "capability": "storage.read",
            "timestamp": time.time(),
        },
    )
    assert response.status_code in {200, 202, 403}


def _track_temporary_files(server, monkeypatch):
    created = []
    modes = []
    original_mkstemp = server.tempfile.mkstemp

    def tracked_mkstemp(*args, **kwargs):
        fd, path = original_mkstemp(*args, **kwargs)
        created.append(Path(path))
        modes.append(stat.S_IMODE(os.stat(path).st_mode))
        return fd, path

    monkeypatch.setattr(server.tempfile, "mkstemp", tracked_mkstemp)
    return created, modes


def test_audit_downloads_are_private_and_removed(tmp_path, monkeypatch):
    server, client = _client(tmp_path, monkeypatch)
    created, modes = _track_temporary_files(server, monkeypatch)

    with client:
        _create_record(client)

        records = client.get("/v1/audit/export")
        envelopes = client.get("/v1/audit/envelopes")

        assert records.status_code == 200
        assert envelopes.status_code == 200
        assert records.text.strip()
        assert json.loads(envelopes.text.splitlines()[0])["public_key"]

        assert modes == [0o600, 0o600]
        assert len(created) == 2
        assert all(not path.exists() for path in created)


def test_failed_export_removes_temporary_file(tmp_path, monkeypatch):
    server, client = _client(tmp_path, monkeypatch)
    created, _ = _track_temporary_files(server, monkeypatch)

    with client:

        def fail_export(path):
            raise RuntimeError("simulated export failure")

        monkeypatch.setattr(
            server.state["store"],
            "export_jsonl",
            fail_export,
        )

        with pytest.raises(RuntimeError, match="simulated export failure"):
            client.get("/v1/audit/export")

        assert len(created) == 1
        assert not created[0].exists()
