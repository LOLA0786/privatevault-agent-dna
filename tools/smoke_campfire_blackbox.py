#!/usr/bin/env python3
"""Smoke the Campfire black-box protocol against a real composed runtime.

Uses ephemeral keys in a temporary directory. Never sets PV_ALLOW_NO_AUTH.
Exit nonzero on any failure. Does not claim a recording transport delivered
bytes to a network peer.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from agent_dna.execution_v01 import (  # noqa: E402
    sha256_bytes_digest,
    verify_execution_authorization,
)
from agent_dna.signer import verify_trusted_envelope  # noqa: E402

_INIT_SPEC = importlib.util.spec_from_file_location(
    "init_campfire_blackbox", ROOT / "tools" / "init_campfire_blackbox.py"
)
assert _INIT_SPEC is not None and _INIT_SPEC.loader is not None
_init = importlib.util.module_from_spec(_INIT_SPEC)
_INIT_SPEC.loader.exec_module(_init)
AGENT_ID = _init.AGENT_ID
CAPABILITY = _init.CAPABILITY
ORG = _init.ORG
bootstrap = _init.bootstrap

PACK = ROOT / "deploy" / "partners" / "campfire-blackbox" / "partner-pack"
Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"path":"/sandbox/notes.txt","content":"hello from the evaluation sandbox"}'
PEER = b"tls-spki:sandbox.campfire.eval:v1"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _example(name: str) -> dict:
    payload = json.loads(
        (PACK / "examples" / f"{name}.json").read_text(encoding="utf-8")
    )
    payload["timestamp"] = time.time()
    payload["request_id"] = f"{payload['request_id']}-{int(time.time() * 1000)}"
    return payload


def _secrets(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key] = value
    return out


def _apply_env(runtime: Path, secrets: dict[str, str], db: Path) -> None:
    os.environ.pop("PV_ALLOW_NO_AUTH", None)
    os.environ.pop("PV_SECURE_PROFILE", None)
    os.environ["PV_DB_PATH"] = str(db)
    os.environ["PV_API_KEYS_FILE"] = str(runtime / "keys.json")
    os.environ["PV_GRANTS_FILE"] = str(runtime / "grants.json")
    os.environ["PV_POLICY_FILE"] = str(runtime / "policy.yaml")
    os.environ["PV_EXECUTION_SIGNER_KEY"] = str(runtime / "execution-signer.key")
    os.environ["PV_TRUST_BUNDLE"] = str(runtime / "trust-bundle.json")
    os.environ["PV_EXECUTION_TRUST_BUNDLE_FILE"] = str(
        runtime / "execution-trust-bundle.json"
    )
    os.environ["PV_DISPATCH_WITNESS_KEY"] = str(runtime / "dispatch-witness.key")
    os.environ["PV_RECEIPT_SIGNING_KEY"] = secrets["PV_RECEIPT_SIGNING_KEY"]
    os.environ["PV_TRUSTED_PUBLIC_KEYS"] = secrets["PV_TRUSTED_PUBLIC_KEY"]
    os.environ["PV_ORGANISATION_ID"] = ORG
    os.environ["PV_BASELINE_CAPABILITIES"] = CAPABILITY


def _ea_dispatch(context: dict[str, str]) -> dict:
    return {
        "transport": context["transport"],
        "destination": context["destination"],
        "operation": context["operation"],
        "wire_content_type": context["wire_content_type"],
        "wire_content_encoding": "identity",
        "tool_id": f"{CAPABILITY}.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": context["destination"],
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
    }


def _authorize_body(
    record: dict, action: dict, dispatch: dict, request_id: str
) -> dict:
    return {
        "request_id": request_id,
        "agent_id": AGENT_ID,
        "organisation_id": ORG,
        "decision_id": record["decision_id"],
        "action": action,
        "dispatch": dispatch,
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": "sha256:" + record["record_hash"],
        "authority_receipt_digest": ONE,
        "approval_artifact_digest": Z,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }


def run_smoke() -> int:  # noqa: C901 - ordered protocol checklist
    demo = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "adversarial_egress_demo.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if demo.returncode != 0:
        _fail(f"exact-byte reference demo {demo.stdout} {demo.stderr}")

    with tempfile.TemporaryDirectory(prefix="pv-campfire-smoke-") as tmp:
        root = Path(tmp)
        runtime = root / "runtime"
        bootstrap(runtime)
        secrets = _secrets(runtime / "keys.secrets.txt")
        _apply_env(runtime, secrets, root / "pv.db")

        import api.server as server

        server._pv_signer_cache.clear()
        importlib.reload(server)
        server._pv_signer_cache.clear()

        full = secrets["CAMPFIRE_API_KEY"]
        audit = secrets["CAMPFIRE_AUDIT_KEY"]
        evidence: list[str] = []

        with TestClient(server.app) as client:
            health = client.get("/health")
            ready = client.get("/ready")
            if health.status_code != 200 or ready.status_code != 200:
                _fail(f"health/ready {health.status_code}/{ready.status_code}")

            audit_decide = client.post(
                "/v1/decide",
                headers={"X-API-Key": audit},
                json=_example("allow"),
            )
            if audit_decide.status_code != 401:
                _fail(f"audit key decide got {audit_decide.status_code}")
            evidence.append("audit-key-cannot-decide")

            allow = client.post(
                "/v1/decide", headers={"X-API-Key": full}, json=_example("allow")
            )
            if allow.status_code != 200:
                _fail(f"ALLOW {allow.status_code} {allow.text}")
            allow_body = allow.json()
            if allow_body["decision"] != "allow":
                _fail(f"ALLOW decision {allow_body['decision']}")
            record = allow_body["record"]
            if record.get("protocol_version") != "drp/0.2":
                _fail(f"ALLOW protocol {record.get('protocol_version')}")
            evidence.append(f"allow record_hash={record['record_hash']}")

            review = client.post(
                "/v1/decide", headers={"X-API-Key": full}, json=_example("review")
            )
            if review.status_code != 202:
                _fail(f"REVIEW {review.status_code} {review.text}")
            review_record = review.json()["record"]
            evidence.append("review=202 no-dispatch")

            block = client.post(
                "/v1/decide", headers={"X-API-Key": full}, json=_example("block")
            )
            if block.status_code != 403:
                _fail(f"BLOCK {block.status_code} {block.text}")
            evidence.append("block=403 no-dispatch")

            action = dict(_example("allow")["execution_action"])
            dispatch = _ea_dispatch(_example("allow")["dispatch_context"])

            review_mint = client.post(
                "/v1/authorize",
                headers={"X-API-Key": full},
                json=_authorize_body(
                    review_record, action, dispatch, "req-review-must-fail"
                ),
            )
            if review_mint.status_code == 200:
                _fail("REVIEW minted a permit")
            block_mint = client.post(
                "/v1/authorize",
                headers={"X-API-Key": full},
                json=_authorize_body(
                    block.json()["record"], action, dispatch, "req-block-must-fail"
                ),
            )
            if block_mint.status_code == 200:
                _fail("BLOCK minted a permit")

            mutated_action = dict(action)
            mutated_action["parameters"] = {
                **action["parameters"],
                "path": "/protected/secrets.txt",
            }
            mut_action = client.post(
                "/v1/authorize",
                headers={"X-API-Key": full},
                json=_authorize_body(
                    record, mutated_action, dispatch, "req-mut-action"
                ),
            )
            if mut_action.status_code == 200:
                _fail("mutated action minted")
            evidence.append(f"mutated-action refused {mut_action.status_code}")

            mutated_dispatch = dict(dispatch)
            mutated_dispatch["destination"] = "evil.example"
            mut_dispatch = client.post(
                "/v1/authorize",
                headers={"X-API-Key": full},
                json=_authorize_body(
                    record, action, mutated_dispatch, "req-mut-dispatch"
                ),
            )
            if mut_dispatch.status_code == 200:
                _fail("mutated dispatch minted")
            evidence.append(f"mutated-dispatch refused {mut_dispatch.status_code}")

            swap = _authorize_body(record, action, dispatch, "req-swap")
            swap["decision_id"] = "dec-missing"
            swap["decision_receipt_digest"] = ONE
            swapped = client.post(
                "/v1/authorize", headers={"X-API-Key": full}, json=swap
            )
            if swapped.status_code == 200:
                _fail("record substitution minted")
            evidence.append(f"substitution refused {swapped.status_code}")

            minted = client.post(
                "/v1/authorize",
                headers={"X-API-Key": full},
                json=_authorize_body(record, action, dispatch, "req-honest"),
            )
            if minted.status_code != 200:
                _fail(f"honest authorize {minted.status_code} {minted.text}")
            minted_body = minted.json()
            report = verify_execution_authorization(
                minted_body["authorization"],
                minted_body["trust_bundle"],
                expected_request_id="req-honest",
                expected_action=action,
                expected_dispatch=dispatch,
                expected_decision_receipt_digest="sha256:" + record["record_hash"],
                expected_authority_receipt_digest=ONE,
                expected_approval_artifact_digest=Z,
                expected_state_snapshot_digest=Z,
                expected_policy_bundle_digest=ONE,
                expected_obligations_digest=Z,
                expected_wire_bytes=WIRE,
                expected_peer_identity_bytes=PEER,
                at_time=minted_body["at_time"],
                already_consumed=False,
                consume_ledger=server.state["store"],
            )
            if not report.ok:
                _fail(f"permit verify failed {report}")
            evidence.append(
                f"permit {minted_body['authorization']['execution_authorization_id']}"
            )

            outcome = client.post(
                "/v1/outcome",
                headers={"X-API-Key": full},
                json={
                    "decision_id": record["decision_id"],
                    "status": "ok",
                    "detail": "evaluation sandbox write not dispatched by this smoke",
                },
            )
            if outcome.status_code != 200:
                _fail(f"outcome {outcome.status_code} {outcome.text}")

            verify = client.get("/v1/verify", headers={"X-API-Key": audit})
            if verify.status_code != 200:
                _fail(f"verify {verify.status_code}")
            if not verify.json().get("chain_integrity_verified"):
                _fail(f"chain verify {verify.json()}")
            evidence.append("chain_integrity_verified=true")

            export = client.get("/v1/audit/export", headers={"X-API-Key": audit})
            if export.status_code != 200:
                _fail(f"export {export.status_code}")
            export_path = root / "export.jsonl"
            export_path.write_bytes(export.content)
            verifier = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_records.py"),
                    str(export_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if verifier.returncode != 0:
                _fail(f"independent verifier {verifier.stdout} {verifier.stderr}")
            evidence.append("independent verifier PASS")

            envelope = client.get(
                f"/v1/envelope/{record['record_hash']}",
                headers={"X-API-Key": full},
            )
            if envelope.status_code != 200:
                _fail(f"envelope {envelope.status_code} {envelope.text}")
            env = envelope.json()["envelope"]
            trusted = {secrets["PV_TRUSTED_PUBLIC_KEY"]}
            if not verify_trusted_envelope(
                env, record["record_hash"], trusted_keys=trusted
            ):
                _fail("detached signature did not verify against supplied public key")
            evidence.append("detached envelope verified with independent public key")

        evidence.append(
            "exact-byte recording-transport demo: honest accepted, "
            "mutated refused, replay refused, witness verified "
            "(does not prove network delivery)"
        )

        print("CAMPFIRE BLACKBOX SMOKE PASS")
        for line in evidence:
            print(f"  {line}")
        print(
            "INDETERMINATE executions must not be retried automatically; "
            "treat the permit as burned unless independent evidence shows "
            "the first attempt did not execute."
        )
        print("This smoke does not prove Campfire's real tool path is mediated.")
        return 0


def main() -> int:
    try:
        return run_smoke()
    except SystemExit:
        raise
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
