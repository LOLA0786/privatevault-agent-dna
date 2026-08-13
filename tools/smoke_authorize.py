#!/usr/bin/env python3
"""Mint a permit through the real endpoint and verify it with the real verifier."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.execution_v01 import (
    sha256_bytes_digest,
    verify_execution_authorization,
)

Z = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = os.environ.get("PV_ORGANISATION_ID", "store.example")
AGENT = "refund-agent-01"
ARGS = {"case_id": "case-7821"}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        op = generate_key(AGENT, "full")
        keys_path = root / "keys.json"
        keys_path.write_text(
            json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
            encoding="utf-8",
        )
        sk = SigningKey.generate()
        key_path = root / "exec.key"
        key_path.write_bytes(bytes(sk))
        bundle = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": ORG,
            "bundle_version": 1,
            "pinned_at": "2026-07-31T11:00:00Z",
            "keys": [
                {
                    "key_id": "execution-signer-01",
                    "principal": f"execution-runtime@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(sk),
                    "usages": ["execution_authorization_signer"],
                }
            ],
        }
        bundle_path = root / "trust.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        os.environ["PV_DB_PATH"] = str(root / "pv.db")
        os.environ["PV_API_KEYS_FILE"] = str(keys_path)
        os.environ["PV_EXECUTION_SIGNER_KEY"] = str(key_path)
        os.environ["PV_TRUST_BUNDLE"] = str(bundle_path)
        os.environ.pop("PV_ALLOW_NO_AUTH", None)

        import importlib

        from fastapi.testclient import TestClient

        import api.server as server

        server._pv_signer_cache.clear()
        importlib.reload(server)
        server._pv_signer_cache.clear()

        action = {
            "subject_principal": f"{AGENT}@{ORG}",
            "subject_key_id": AGENT,
            "action": "crm.read_contact",
            "resource": "crm:contact",
            "parameters": dict(ARGS),
        }
        dispatch = {
            "transport": "https",
            "destination": "crm.store.example",
            "operation": "GET /v1/contacts",
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "tool_id": "crm.read_contact.v1",
            "tool_schema_digest": Z,
            "tool_artifact_digest": ONE,
            "credential_audience": "crm.store.example",
            "idempotency_key_digest": Z,
            "retry_policy_digest": ONE,
        }

        with TestClient(server.app) as client:
            decided = client.post(
                "/v1/decide",
                headers={"X-API-Key": op["key"]},
                json={
                    "agent_id": AGENT,
                    "capability": "crm.read_contact",
                    "timestamp": time.time(),
                    "arguments": dict(ARGS),
                },
            )
            if decided.status_code != 200:
                sys.exit(
                    f"SMOKE TEST FAILED: decide {decided.status_code} {decided.text}"
                )
            record = decided.json()["record"]
            receipt = "sha256:" + record["record_hash"]
            minted = client.post(
                "/v1/authorize",
                headers={"X-API-Key": op["key"]},
                json={
                    "request_id": "request-001",
                    "agent_id": AGENT,
                    "organisation_id": ORG,
                    "decision_id": record["decision_id"],
                    "action": action,
                    "dispatch": dispatch,
                    "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
                    "expected_wire_bytes_length": len(WIRE),
                    "expected_peer_identity_digest": sha256_bytes_digest(PEER),
                    "decision_receipt_digest": receipt,
                    "authority_receipt_digest": ONE,
                    "approval_artifact_digest": Z,
                    "state_snapshot_digest": Z,
                    "policy_bundle_digest": ONE,
                    "obligations_digest": Z,
                },
            )
            if minted.status_code != 200:
                sys.exit(
                    f"SMOKE TEST FAILED: authorize {minted.status_code} {minted.text}"
                )
            result = minted.json()
            store = server.state["store"]

            authorization = result["authorization"]
            trust_bundle = result["trust_bundle"]

            report = verify_execution_authorization(
                authorization,
                trust_bundle,
                expected_request_id="request-001",
                expected_action=action,
                expected_dispatch=dispatch,
                expected_decision_receipt_digest=receipt,
                expected_authority_receipt_digest=ONE,
                expected_approval_artifact_digest=Z,
                expected_state_snapshot_digest=Z,
                expected_policy_bundle_digest=ONE,
                expected_obligations_digest=Z,
                expected_wire_bytes=WIRE,
                expected_peer_identity_bytes=PEER,
                at_time=result["at_time"],
                already_consumed=False,
                consume_ledger=store,
            )

            print("permit id   :", authorization["execution_authorization_id"])
            print("max_uses    :", authorization["max_uses"])
            print("signer      :", authorization["signer_key_id"])
            print(
                "verifies    :",
                report.ok,
                "|",
                report.evidence_state,
                "|",
                report.decision_conformance,
            )

            decided2 = client.post(
                "/v1/decide",
                headers={"X-API-Key": op["key"]},
                json={
                    "agent_id": AGENT,
                    "capability": "crm.read_contact",
                    "timestamp": time.time(),
                    "arguments": dict(ARGS),
                },
            )
            record2 = decided2.json()["record"]
            receipt2 = "sha256:" + record2["record_hash"]
            minted2 = client.post(
                "/v1/authorize",
                headers={"X-API-Key": op["key"]},
                json={
                    "request_id": "request-002",
                    "agent_id": AGENT,
                    "organisation_id": ORG,
                    "decision_id": record2["decision_id"],
                    "action": action,
                    "dispatch": dispatch,
                    "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
                    "expected_wire_bytes_length": len(WIRE),
                    "expected_peer_identity_digest": sha256_bytes_digest(PEER),
                    "decision_receipt_digest": receipt2,
                    "authority_receipt_digest": ONE,
                    "approval_artifact_digest": Z,
                    "state_snapshot_digest": Z,
                    "policy_bundle_digest": ONE,
                    "obligations_digest": Z,
                },
            )
            result2 = minted2.json()

            tampered = verify_execution_authorization(
                result2["authorization"],
                result2["trust_bundle"],
                expected_request_id="request-002",
                expected_action=action,
                expected_dispatch=dispatch,
                expected_decision_receipt_digest=receipt2,
                expected_authority_receipt_digest=ONE,
                expected_approval_artifact_digest=Z,
                expected_state_snapshot_digest=Z,
                expected_policy_bundle_digest=ONE,
                expected_obligations_digest=Z,
                expected_wire_bytes=b'{"account":"4471","amount":900000}',
                expected_peer_identity_bytes=PEER,
                at_time=result2["at_time"],
                already_consumed=False,
                consume_ledger=store,
            )
            print("tampered    :", tampered.ok, "|", tampered.evidence_state)

            if not report.ok or tampered.ok:
                sys.exit("SMOKE TEST FAILED")
            print(
                "\nOK - permit binds sealed ALLOW + exact bytes "
                "and rejects substitution"
            )
            print(
                "For verify+witness+send (reference egress adapter), run:\n"
                "  uv run python tools/adversarial_egress_demo.py"
            )


if __name__ == "__main__":
    main()
