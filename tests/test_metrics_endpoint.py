"""Regression: /metrics previously raised NameError (undefined body /
content_type) on every call. It must return 200 with Prometheus
text-format exposition regardless of whether prometheus_client is
installed."""

import importlib

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_DB", str(tmp_path / "keys.db"))
    monkeypatch.setenv("PV_AUTH_DISABLED", "1")
    import api.server as server

    importlib.reload(server)
    return TestClient(server.app)


def test_metrics_returns_200_text(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert r.text.strip() != ""
    assert not r.text.lstrip().startswith("{")
