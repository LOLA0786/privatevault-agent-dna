"""The two operator-facing surfaces added with the 2026-11 fixes, on the
real app: GET /v1/audit/checkpoint, and a quorum pinned by PV_CONSENSUS_FILE."""

import importlib
import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from agent_dna.consensus.signing import (
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.signer import generate_keypair
from tests.decide_binding import decide_json

KEYS = generate_keypair()
VOTERS = {name: generate_voter_keypair() for name in ("fraud", "finance", "legal")}
AGENT, CAP = "pay-agent", "payments.pay_invoice"
ARGS = {"amount": 9_000_000}


def _client(tmp_path, monkeypatch, *, consensus=None):
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [
                {"agent_id": AGENT, "capability": cap, "granted_by": "ops"}
                for cap in (CAP, "crm.read_contact")
            ]
        )
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", f"{CAP},crm.read_contact")
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", KEYS["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", KEYS["public_key"])
    if consensus is None:
        monkeypatch.delenv("PV_CONSENSUS_FILE", raising=False)
    else:
        path = tmp_path / "consensus.json"
        path.write_text(json.dumps(consensus))
        monkeypatch.setenv("PV_CONSENSUS_FILE", str(path))
    import api.server as server

    importlib.reload(server)
    return TestClient(server.app)


def _roster(**extra):
    return {
        "threshold": 2.0,
        "voters": [
            {"agent_id": name, "weight": 1.0, "public_key": keys["public_key"]}
            for name, keys in VOTERS.items()
        ],
        **extra,
    }


def _votes(*names, arguments=ARGS):
    action_id = consensus_action_id(AGENT, CAP, arguments)
    return {
        "consensus": {
            "action_id": action_id,
            "votes": [
                cast_vote_v2(
                    VOTERS[name]["signing_key"],
                    agent_id=name,
                    action_id=action_id,
                    vote="APPROVE",
                )
                for name in names
            ],
        }
    }


def _decide(client, evidence=None, arguments=ARGS):
    extra = {"evidence": evidence} if evidence is not None else {}
    return client.post(
        "/v1/decide", json=decide_json(AGENT, CAP, arguments=arguments, **extra)
    )


# ---- quorum on the live server --------------------------------------------


def test_pinned_roster_lets_a_real_quorum_clear(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, consensus=_roster()) as client:
        cleared = _decide(client, _votes("fraud", "finance"))
        assert cleared.status_code == 200, cleared.text
        short = _decide(client, _votes("fraud"))
        assert short.status_code == 202
        assert short.json()["triggered_by"] == "consensus"
        detail = client.get("/v1/runtime").json()["composition"]["consensus"]["detail"]
        assert "3 pinned voter(s)" in detail


def test_required_capability_without_votes_is_held(tmp_path, monkeypatch):
    roster = _roster(required_for=["payments."])
    with _client(tmp_path, monkeypatch, consensus=roster) as client:
        held = _decide(client)
        assert held.status_code == 202
        assert "consensus_required" in held.json()["reason"]
        assert _decide(client, _votes("fraud", "legal")).status_code == 200


def test_votes_do_not_follow_a_changed_amount(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, consensus=_roster()) as client:
        votes = _votes("fraud", "finance", arguments={"amount": 10})
        moved = _decide(client, votes, arguments={"amount": 9_000_000})
        assert moved.status_code == 202
        assert "consensus_action_mismatch" in moved.json()["reason"]


def test_without_a_roster_supplied_votes_are_held(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        held = _decide(client, _votes("fraud", "finance"))
        assert held.status_code == 202
        assert "consensus_not_configured" in held.json()["reason"]


def test_invalid_roster_refuses_startup(tmp_path, monkeypatch):
    from agent_dna.consensus import ConsensusConfigError

    bad = _roster(threshold=1.0)  # not more than half of total weight 3
    with pytest.raises(ConsensusConfigError, match="not more than half"):
        with _client(tmp_path, monkeypatch, consensus=bad):
            pass


# ---- checkpoint endpoint ---------------------------------------------------


def test_checkpoint_endpoint_catches_a_truncated_export(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        for _ in range(3):
            assert _decide(client).status_code == 200
        checkpoint = client.get("/v1/audit/checkpoint").json()
        assert checkpoint["record_count"] == 3
        assert checkpoint["signature"]["public_key"] == KEYS["public_key"]
        records = client.get("/v1/audit/export").text
        envelopes = client.get("/v1/audit/envelopes").text

    (tmp_path / "cp.json").write_text(json.dumps(checkpoint))
    (tmp_path / "full.jsonl").write_text(records)
    (tmp_path / "full.env").write_text(envelopes)
    kept = records.splitlines()[:2]
    hashes = {json.loads(line)["record_hash"] for line in kept}
    (tmp_path / "cut.jsonl").write_text("\n".join(kept) + "\n")
    (tmp_path / "cut.env").write_text(
        "".join(
            line + "\n"
            for line in envelopes.splitlines()
            if json.loads(line)["signed_hash"] in hashes
        )
    )

    def verify(name, with_checkpoint=True):
        command = [
            sys.executable,
            "tools/verify_records.py",
            str(tmp_path / f"{name}.jsonl"),
            "--envelopes",
            str(tmp_path / f"{name}.env"),
            "--trusted-key",
            KEYS["public_key"],
        ]
        if with_checkpoint:
            command += ["--checkpoint", str(tmp_path / "cp.json")]
        return subprocess.run(command, capture_output=True, text=True, check=False)

    assert verify("full").returncode == 0
    assert verify("cut", with_checkpoint=False).returncode == 0  # the blind spot
    cut = verify("cut")
    assert cut.returncode == 1
    assert "INCOMPLETE EXPORT" in cut.stdout
