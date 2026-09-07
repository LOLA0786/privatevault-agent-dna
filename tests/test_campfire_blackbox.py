"""Campfire hosted black-box evaluation pack.

Adversarial coverage for bootstrap, ZIP allowlisting, and mint binding.
Does not ship runtime source or signing material to the partner.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PACK_SRC = ROOT / "deploy" / "partners" / "campfire-blackbox" / "partner-pack"
AGENT = "campfire-agent"
CAPABILITY = "campfire.files.write_sandbox"
ORG = "campfire.eval"

ALLOWLIST = (
    "README.md",
    "API.yaml",
    "Campfire-PrivateVault.postman_collection.json",
    "TEST-PLAN.md",
    "LIMITATIONS.md",
    "examples/allow.json",
    "examples/review.json",
    "examples/block.json",
    "MANIFEST.json",
    "SHA256SUMS",
)


def _load_tool(name: str) -> Any:
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"campfire_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def init_mod():
    return _load_tool("init_campfire_blackbox")


@pytest.fixture(scope="module")
def build_mod():
    return _load_tool("build_campfire_partner_pack")


def _bootstrap(init_mod, dest: Path, **kwargs):
    return init_mod.bootstrap(dest, **kwargs)


def test_bootstrap_writes_hashed_keys_and_restrictive_perms(tmp_path, init_mod):
    out = tmp_path / "runtime"
    result = _bootstrap(init_mod, out)
    keys = json.loads((out / "keys.json").read_text(encoding="utf-8"))
    assert keys, "registry must be non-empty"
    names = {entry["name"] for entry in keys.values()}
    scopes = {entry["name"]: entry["scope"] for entry in keys.values()}
    assert names == {AGENT, "campfire-auditor"}
    assert scopes[AGENT] == "full"
    assert scopes["campfire-auditor"] == "audit"
    for digest in keys:
        assert len(digest) == 64
        int(digest, 16)
    secrets = out / "keys.secrets.txt"
    mode = stat.S_IMODE(secrets.stat().st_mode)
    assert mode == 0o600
    text = secrets.read_text(encoding="utf-8")
    assert "CAMPFIRE_API_KEY=pv_" in text
    assert "CAMPFIRE_AUDIT_KEY=pv_" in text
    registry_blob = (out / "keys.json").read_text(encoding="utf-8")
    assert "pv_" not in registry_blob
    for name in ("execution-signer.key", "dispatch-witness.key"):
        path = out / name
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert result["agent_id"] == AGENT
    assert "api_key" not in result
    assert "signing_key" not in result


def test_bootstrap_refuses_overwrite(tmp_path, init_mod):
    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        _bootstrap(init_mod, out)
    _bootstrap(init_mod, out, replace_existing=True)
    assert (out / "keys.json").is_file()


def test_bootstrap_prints_no_secrets(tmp_path, init_mod, capsys):
    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    secrets = (out / "keys.secrets.txt").read_text(encoding="utf-8")
    for line in secrets.splitlines():
        if "=" in line:
            _, _, value = line.partition("=")
            if value.strip():
                assert value.strip() not in combined
    assert "BEGIN" not in combined
    assert (
        "PV_RECEIPT_SIGNING_KEY=" not in combined
        or "PV_RECEIPT_SIGNING_KEY=<" in combined
    )


def test_bootstrap_identity_binding_and_scopes(tmp_path, init_mod, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        denied = client.post(
            "/v1/decide",
            headers={"X-API-Key": secrets["CAMPFIRE_AUDIT_KEY"]},
            json=_example("allow"),
        )
        assert denied.status_code == 401
        other = dict(_example("allow"))
        other["agent_id"] = "not-campfire"
        other["execution_action"]["subject_key_id"] = "not-campfire"
        bound = client.post(
            "/v1/decide",
            headers={"X-API-Key": secrets["CAMPFIRE_API_KEY"]},
            json=other,
        )
        assert bound.status_code == 403


def test_undispatched_http_outcome_cannot_be_recorded_as_ok(
    tmp_path, init_mod, monkeypatch
):
    import importlib

    from fastapi.testclient import TestClient

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        key = secrets["CAMPFIRE_API_KEY"]
        decided = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("allow")
        )
        assert decided.status_code == 200, decided.text
        decision_id = decided.json()["record"]["decision_id"]
        false_ok = client.post(
            "/v1/outcome",
            headers={"X-API-Key": key},
            json={
                "decision_id": decision_id,
                "status": "ok",
                "dispatched": False,
                "detail": "tool was not dispatched",
            },
        )
        assert false_ok.status_code == 409, false_ok.text
        assert "dispatched=true" in false_ok.json()["detail"]
        omitted = client.post(
            "/v1/outcome",
            headers={"X-API-Key": key},
            json={
                "decision_id": decision_id,
                "status": "ok",
                "detail": "tool was not dispatched",
            },
        )
        assert omitted.status_code == 409, omitted.text
        assert "dispatched=true" in omitted.json()["detail"]
        null_ok = client.post(
            "/v1/outcome",
            headers={"X-API-Key": key},
            json={
                "decision_id": decision_id,
                "status": "ok",
                "dispatched": None,
                "detail": "tool was not dispatched",
            },
        )
        assert null_ok.status_code == 409, null_ok.text
        assert "dispatched=true" in null_ok.json()["detail"]
        honest = client.post(
            "/v1/outcome",
            headers={"X-API-Key": key},
            json={
                "decision_id": decision_id,
                "status": "refused",
                "dispatched": False,
                "detail": "tool was not dispatched",
            },
        )
        assert honest.status_code == 200, honest.text
        event = honest.json()["event"]
        assert event["status"] == "refused"
        assert event["status"] != "ok"


def test_runtime_manifest_exposes_baseline_override(tmp_path, init_mod, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        shown = client.get(
            "/v1/runtime", headers={"X-API-Key": secrets["CAMPFIRE_API_KEY"]}
        )
        assert shown.status_code == 200, shown.text
        baseline = shown.json()["composition"]["baseline_capabilities"]
        assert baseline["override"] == "true"
        assert baseline["capabilities"] == [CAPABILITY]


def test_postman_uses_dynamic_unix_timestamp():
    text = (PACK_SRC / "Campfire-PrivateVault.postman_collection.json").read_text(
        encoding="utf-8"
    )
    assert "{{$timestamp}}" in text
    assert "1753000000" not in text


def test_examples_instruct_current_unix_timestamp():
    for name in ("allow.json", "review.json", "block.json"):
        payload = json.loads((PACK_SRC / "examples" / name).read_text(encoding="utf-8"))
        instruction = payload["_timestamp_instruction"].lower()
        assert "current unix time" in instruction
        assert "timestamp" in instruction


def _pack_postman_body(name: str) -> str:
    collection = json.loads(
        (PACK_SRC / "Campfire-PrivateVault.postman_collection.json").read_text(
            encoding="utf-8"
        )
    )
    for item in collection["item"]:
        if item["name"] == name:
            return item["request"]["body"]["raw"]
    raise AssertionError(f"missing Postman item {name}")


def test_partner_pack_honest_authorize_returns_200(tmp_path, init_mod, monkeypatch):
    """Follow only partner-pack files. No hidden in-repo dispatch fixtures."""
    import importlib
    import time

    from fastapi.testclient import TestClient

    readme = (PACK_SRC / "README.md").read_text(encoding="utf-8")
    assert "PV_SECURE_PROFILE=1" in readme
    assert "does not dispatch" in readme.lower() or "does not dispatch a file" in readme
    assert "does not prove live network delivery" in readme
    assert "wire_content_encoding" in readme
    assert "Do not send decide `dispatch_context` as `dispatch`" in readme

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    allow = _example("allow")
    allow["timestamp"] = time.time()
    key = secrets["CAMPFIRE_API_KEY"]

    with TestClient(server.app) as client:
        decided = client.post("/v1/decide", headers={"X-API-Key": key}, json=allow)
        assert decided.status_code == 200, decided.text
        record = decided.json()["record"]
        decision_id = record["decision_id"]
        record_hash = record["record_hash"]

        def load_authorize(name: str) -> dict[str, Any]:
            raw = _pack_postman_body(name)
            filled = raw.replace("{{decision_id}}", decision_id).replace(
                "{{record_hash}}", record_hash
            )
            body = json.loads(filled)
            assert "adapter" not in body["dispatch"]
            assert set(body["dispatch"]) == {
                "transport",
                "destination",
                "operation",
                "wire_content_type",
                "wire_content_encoding",
                "tool_id",
                "tool_schema_digest",
                "tool_artifact_digest",
                "credential_audience",
                "idempotency_key_digest",
                "retry_policy_digest",
            }
            return body

        honest = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=load_authorize("POST authorize (honest)"),
        )
        assert honest.status_code == 200, honest.text
        assert honest.json()["authorization"]["signature"]
        assert honest.json()["authorization"]["max_uses"] == 1

        changed_path = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=load_authorize("POST authorize (changed path)"),
        )
        assert changed_path.status_code == 403, changed_path.text
        assert (
            changed_path.json()["detail"]["reason_code"]
            == "AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH"
        )

        changed_dest = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=load_authorize("POST authorize (changed destination)"),
        )
        assert changed_dest.status_code == 403, changed_dest.text
        assert (
            changed_dest.json()["detail"]["reason_code"]
            == "AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH"
        )


def test_generated_policy_is_deterministic_allow_review_block(
    tmp_path, init_mod, monkeypatch
):
    import importlib
    import time

    from fastapi.testclient import TestClient

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        key = secrets["CAMPFIRE_API_KEY"]
        allow = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("allow")
        )
        review = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("review")
        )
        block = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("block")
        )
        assert allow.status_code == 200, allow.text
        assert allow.json()["decision"] == "allow"
        assert allow.json()["triggered_by"] != "drift"
        assert allow.json()["record"]["protocol_version"] == "drp/0.2"
        assert review.status_code == 202, review.text
        assert review.json()["decision"] == "require_approval"
        assert block.status_code == 403, block.text
        assert block.json()["decision"] == "block"
        # timestamp is unused for the assertion above; keep import honest
        assert time.time() > 0


def test_partner_zip_allowlist_and_checksums(tmp_path, build_mod):
    dest = tmp_path / "campfire.zip"
    build_mod.build_partner_pack(
        source=PACK_SRC,
        dest=dest,
        git_commit="deadbeef",
        build_time="2026-08-19T00:00:00Z",
        version="0.4.0",
    )
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
        assert names == sorted(ALLOWLIST)
        assert "INTERNAL-DEPLOYMENT.md" not in names
        manifest = json.loads(zf.read("MANIFEST.json"))
        assert manifest["product_version"] == "0.4.0"
        assert manifest["git_commit"] == "deadbeef"
        assert manifest["build_time"] == "2026-08-19T00:00:00Z"
        sums = zf.read("SHA256SUMS").decode("utf-8")
        for name in names:
            if name in ("MANIFEST.json", "SHA256SUMS"):
                continue
            digest = hashlib.sha256(zf.read(name)).hexdigest()
            assert f"{digest}  {name}" in sums


def test_zip_reproducible_from_identical_inputs(tmp_path, build_mod):
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    kwargs = {
        "source": PACK_SRC,
        "git_commit": "abc123",
        "build_time": "2026-08-19T00:00:00Z",
        "version": "0.4.0",
    }
    build_mod.build_partner_pack(dest=a, **kwargs)
    build_mod.build_partner_pack(dest=b, **kwargs)
    assert (
        hashlib.sha256(a.read_bytes()).hexdigest()
        == hashlib.sha256(b.read_bytes()).hexdigest()
    )


def test_scan_rejects_source_and_secret_markers(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    (dirty / "README.md").write_text(
        (dirty / "README.md").read_text(encoding="utf-8")
        + "\nPV_RECEIPT_SIGNING_KEY=ffffffffffffffff\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "bad.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_examples_and_docs_have_no_private_material():
    assert PACK_SRC.is_dir()
    for path in PACK_SRC.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "pv_" not in text
        assert "BEGIN PRIVATE" not in text
        assert "PV_RECEIPT_SIGNING_KEY" not in text
        assert "action_digest" not in text or path.name in {
            "API.yaml",
            "TEST-PLAN.md",
            "LIMITATIONS.md",
            "README.md",
        }


def test_examples_match_decide_schema():
    for name in ("allow.json", "review.json", "block.json"):
        payload = json.loads((PACK_SRC / "examples" / name).read_text(encoding="utf-8"))
        assert payload["agent_id"] == AGENT
        assert payload["capability"] == CAPABILITY
        assert payload["execution_action"]["subject_key_id"] == payload["agent_id"]
        assert payload["execution_action"]["action"] == payload["capability"]
        assert payload["execution_action"]["parameters"] == payload["arguments"]
        assert "action_digest" not in payload["execution_action"]
        assert "dispatch_context_digest" not in payload["dispatch_context"]
        ctx = payload["dispatch_context"]
        assert set(ctx) == {
            "adapter",
            "transport",
            "operation",
            "destination",
            "wire_content_type",
        }


def test_adversarial_symlink_injection(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    target = tmp_path / "outside.pem"
    target.write_text("BEGIN PRIVATE KEY\n", encoding="utf-8")
    link = dirty / "LIMITATIONS.md"
    link.unlink()
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "sym.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_adversarial_path_traversal(tmp_path, build_mod):
    with pytest.raises(ValueError, match="path"):
        build_mod.assert_safe_member("../evil.md")


def test_adversarial_extra_file_injection(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    (dirty / "agent_dna.py").write_text("print('no')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="allowlist"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "extra.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_adversarial_private_key_marker_injection(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    (dirty / "TEST-PLAN.md").write_text(
        "-----BEGIN EC PRIVATE KEY-----\nMIIB\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "pem.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_adversarial_plaintext_api_key_injection(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    (dirty / "README.md").write_text(
        "use CAMPFIRE_API_KEY=pv_this_is_a_real_looking_token_value\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "key.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_adversarial_lab_seed_injection(tmp_path, build_mod):
    dirty = tmp_path / "pack"
    _copy_pack(PACK_SRC, dirty)
    (dirty / "examples" / "allow.json").write_text(
        json.dumps({"seed-state.json": True, "path": "/sandbox/notes.txt"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden"):
        build_mod.build_partner_pack(
            source=dirty,
            dest=tmp_path / "seed.zip",
            git_commit="x",
            build_time="2026-08-19T00:00:00Z",
            version="0.4.0",
        )


def test_mutating_action_and_dispatch_refuses_mint(tmp_path, init_mod, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    from agent_dna.execution_v01 import sha256_bytes_digest

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    z = "sha256:" + ("0" * 64)
    one = "sha256:" + ("1" * 64)
    wire = b'{"path":"/sandbox/notes.txt","content":"ok"}'
    peer = b"tls-spki:sandbox.campfire.eval:v1"
    key = secrets["CAMPFIRE_API_KEY"]

    with TestClient(server.app) as client:
        decided = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("allow")
        )
        assert decided.status_code == 200, decided.text
        record = decided.json()["record"]
        receipt = "sha256:" + record["record_hash"]
        action = dict(_example("allow")["execution_action"])
        dispatch = _ea_dispatch(_example("allow")["dispatch_context"])
        body = {
            "request_id": "req-allow-1",
            "agent_id": AGENT,
            "organisation_id": ORG,
            "decision_id": record["decision_id"],
            "action": action,
            "dispatch": dispatch,
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(peer),
            "decision_receipt_digest": receipt,
            "authority_receipt_digest": one,
            "approval_artifact_digest": z,
            "state_snapshot_digest": z,
            "policy_bundle_digest": one,
            "obligations_digest": z,
        }
        honest = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
        assert honest.status_code == 200, honest.text

        mutated_action = dict(action)
        mutated_action["parameters"] = {
            **action["parameters"],
            "path": "/protected/secrets.txt",
        }
        bad_action = dict(body)
        bad_action["request_id"] = "req-mut-action"
        bad_action["action"] = mutated_action
        refused_action = client.post(
            "/v1/authorize", headers={"X-API-Key": key}, json=bad_action
        )
        assert refused_action.status_code in {403, 422}

        mutated_dispatch = dict(dispatch)
        mutated_dispatch["destination"] = "evil.example"
        bad_dispatch = dict(body)
        bad_dispatch["request_id"] = "req-mut-dispatch"
        bad_dispatch["dispatch"] = mutated_dispatch
        refused_dispatch = client.post(
            "/v1/authorize", headers={"X-API-Key": key}, json=bad_dispatch
        )
        assert refused_dispatch.status_code in {403, 422}

        swap = dict(body)
        swap["request_id"] = "req-swap"
        swap["decision_id"] = "dec-does-not-exist"
        swap["decision_receipt_digest"] = one
        refused_swap = client.post(
            "/v1/authorize", headers={"X-API-Key": key}, json=swap
        )
        assert refused_swap.status_code in {403, 404, 422}


def test_replayed_authorization_is_refused(tmp_path, init_mod, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    from agent_dna.execution_v01 import (
        sha256_bytes_digest,
        verify_execution_authorization,
    )

    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    secrets = _parse_secrets(out / "keys.secrets.txt")
    _apply_runtime_env(out, secrets, monkeypatch)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    z = "sha256:" + ("0" * 64)
    one = "sha256:" + ("1" * 64)
    wire = b'{"path":"/sandbox/notes.txt","content":"ok"}'
    peer = b"tls-spki:sandbox.campfire.eval:v1"
    key = secrets["CAMPFIRE_API_KEY"]

    with TestClient(server.app) as client:
        decided = client.post(
            "/v1/decide", headers={"X-API-Key": key}, json=_stamped("allow")
        )
        record = decided.json()["record"]
        action = dict(_example("allow")["execution_action"])
        dispatch = _ea_dispatch(_example("allow")["dispatch_context"])
        minted = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json={
                "request_id": "req-replay",
                "agent_id": AGENT,
                "organisation_id": ORG,
                "decision_id": record["decision_id"],
                "action": action,
                "dispatch": dispatch,
                "expected_wire_bytes_digest": sha256_bytes_digest(wire),
                "expected_wire_bytes_length": len(wire),
                "expected_peer_identity_digest": sha256_bytes_digest(peer),
                "decision_receipt_digest": "sha256:" + record["record_hash"],
                "authority_receipt_digest": one,
                "approval_artifact_digest": z,
                "state_snapshot_digest": z,
                "policy_bundle_digest": one,
                "obligations_digest": z,
            },
        )
        assert minted.status_code == 200, minted.text
        authorization = minted.json()["authorization"]
        trust_bundle = minted.json()["trust_bundle"]
        store = server.state["store"]
        first = verify_execution_authorization(
            authorization,
            trust_bundle,
            expected_request_id="req-replay",
            expected_action=action,
            expected_dispatch=dispatch,
            expected_decision_receipt_digest="sha256:" + record["record_hash"],
            expected_authority_receipt_digest=one,
            expected_approval_artifact_digest=z,
            expected_state_snapshot_digest=z,
            expected_policy_bundle_digest=one,
            expected_obligations_digest=z,
            expected_wire_bytes=wire,
            expected_peer_identity_bytes=peer,
            at_time=minted.json()["at_time"],
            already_consumed=False,
            consume_ledger=store,
        )
        assert first.ok
        second = verify_execution_authorization(
            authorization,
            trust_bundle,
            expected_request_id="req-replay",
            expected_action=action,
            expected_dispatch=dispatch,
            expected_decision_receipt_digest="sha256:" + record["record_hash"],
            expected_authority_receipt_digest=one,
            expected_approval_artifact_digest=z,
            expected_state_snapshot_digest=z,
            expected_policy_bundle_digest=one,
            expected_obligations_digest=z,
            expected_wire_bytes=wire,
            expected_peer_identity_bytes=peer,
            at_time=minted.json()["at_time"],
            already_consumed=False,
            consume_ledger=store,
        )
        assert not second.ok


def test_missing_control_material_fails_closed(tmp_path, init_mod):
    out = tmp_path / "runtime"
    _bootstrap(init_mod, out)
    (out / "grants.json").unlink()
    with pytest.raises((FileNotFoundError, ValueError, RuntimeError)):
        init_mod.validate_runtime_dir(out)


def test_smoke_script_succeeds():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "smoke_campfire_blackbox.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    combined = (proc.stdout + proc.stderr).lower()
    assert "must not be retried" in combined or "do not retry" in combined
    assert "outcome=refused" in combined
    assert "tool not dispatched" in combined


def _example(name: str) -> dict[str, Any]:
    payload = json.loads(
        (PACK_SRC / "examples" / f"{name}.json").read_text(encoding="utf-8")
    )
    return {key: value for key, value in payload.items() if not key.startswith("_")}


def _stamped(name: str) -> dict[str, Any]:
    import time

    payload = dict(_example(name))
    payload["timestamp"] = time.time()
    return payload


def _ea_dispatch(context: dict[str, str]) -> dict[str, Any]:
    z = "sha256:" + ("0" * 64)
    one = "sha256:" + ("1" * 64)
    return {
        "transport": context["transport"],
        "destination": context["destination"],
        "operation": context["operation"],
        "wire_content_type": context["wire_content_type"],
        "wire_content_encoding": "identity",
        "tool_id": f"{CAPABILITY}.v1",
        "tool_schema_digest": z,
        "tool_artifact_digest": one,
        "credential_audience": context["destination"],
        "idempotency_key_digest": z,
        "retry_policy_digest": one,
        "serialization": "pv-json-parameters/0.1",
    }


def _parse_secrets(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key] = value
    return out


def _apply_runtime_env(out: Path, secrets: dict[str, str], monkeypatch) -> None:
    monkeypatch.setenv("PV_API_KEYS_FILE", str(out / "keys.json"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(out / "grants.json"))
    monkeypatch.setenv("PV_POLICY_FILE", str(out / "policy.yaml"))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(out / "execution-signer.key"))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(out / "trust-bundle.json"))
    monkeypatch.setenv(
        "PV_EXECUTION_TRUST_BUNDLE_FILE", str(out / "execution-trust-bundle.json")
    )
    monkeypatch.setenv("PV_DISPATCH_WITNESS_KEY", str(out / "dispatch-witness.key"))
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", secrets["PV_RECEIPT_SIGNING_KEY"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", secrets["PV_TRUSTED_PUBLIC_KEY"])
    monkeypatch.setenv("PV_ORGANISATION_ID", ORG)
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", CAPABILITY)


def _copy_pack(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        target = dest / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
