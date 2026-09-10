#!/usr/bin/env python3
"""One-command last-meter demo for a skeptical infrastructure engineer.

In under a minute (no long-lived server), proves:

  1. ALLOW → mint → exact-byte dispatch succeeds
  2. Mutated wire bytes after authorize are refused (nothing sent)
  3. Replay of a consumed EA is refused (nothing sent)
  4. Offline verify_dispatch_witness accepts the honest witness

Uses the reference ExactByteHttpDispatcher and a recording transport
(no network). Exit nonzero on any failure.

  uv run python tools/adversarial_egress_demo.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_dna.authority_v01 import (  # noqa: E402
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED  # noqa: E402
from agent_dna.connector.adapters.exact_byte_http import (  # noqa: E402
    ExactByteContext,
    ExactByteHttpDispatcher,
    RecordingSidecarTransport,
    WitnessSigner,
)
from agent_dna.dispatch_v01 import verify_dispatch_witness  # noqa: E402
from agent_dna.execution_v01 import (  # noqa: E402
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.sqlite_store import SQLiteDecisionStore  # noqa: E402

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
ORG = "demo.example"
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.demo.example:v3"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        runtime_key = SigningKey.generate()
        witness_key = SigningKey.generate()
        trust = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": ORG,
            "bundle_version": 1,
            "pinned_at": "2026-08-10T15:00:00Z",
            "keys": [
                {
                    "key_id": "ea-signer",
                    "principal": f"execution-runtime@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(runtime_key),
                    "usages": ["execution_authorization_signer"],
                },
                {
                    "key_id": "witness-01",
                    "principal": f"egress-witness@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(witness_key),
                    "usages": ["dispatch_witness_signer", "closure_signer"],
                },
            ],
        }
        action = {
            "subject_principal": f"treasury@{ORG}",
            "subject_key_id": "treasury",
            "action": "payments.initiate_wire",
            "resource": "payments:wire",
            "parameters": json.loads(WIRE),
        }
        dispatch = {
            "transport": "https",
            "destination": "payments.demo.example",
            "operation": "POST /v1/wires",
            "wire_content_type": "application/json",
            "serialization": "pv-json-parameters/0.1",
            "wire_content_encoding": "identity",
            "tool_id": "payments.initiate_wire.v1",
            "tool_schema_digest": Z,
            "tool_artifact_digest": ONE,
            "credential_audience": "payments.demo.example",
            "idempotency_key_digest": Z,
            "retry_policy_digest": ONE,
        }
        authorization = sign_execution_authorization(
            {
                "spec": EXECUTION_AUTHORIZATION_SPEC,
                "canonicalization": CANONICALIZATION,
                "execution_authorization_id": f"eauth-{uuid.uuid4()}",
                "organisation_id": ORG,
                "request_id": "req-demo-1",
                "issued_at": at,
                "not_before": at,
                "expires_at": expires,
                "nonce": uuid.uuid4().hex,
                "decision_receipt_digest": Z,
                "authority_receipt_digest": ONE,
                "approval_artifact_digest": Z,
                "action": action,
                "action_digest": sha256_digest(action),
                "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
                "expected_wire_bytes_length": len(WIRE),
                "expected_peer_identity_digest": sha256_bytes_digest(PEER),
                "dispatch": dispatch,
                "state_snapshot_digest": Z,
                "policy_bundle_digest": ONE,
                "trust_bundle_digest": sha256_digest(trust),
                "obligations_digest": Z,
                "max_uses": 1,
                "signer_key_id": "ea-signer",
            },
            runtime_key,
        )
        store = SQLiteDecisionStore(str(root / "consume.db"))
        transport = RecordingSidecarTransport(peer_identity=PEER)
        dispatcher = ExactByteHttpDispatcher(
            consume_ledger=store,
            witness=WitnessSigner(
                signing_key=witness_key,
                signer_key_id="witness-01",
                witness_component_id="adversarial-egress-demo",
                closure_signer_key_id="witness-01",
                closure_signing_key=witness_key,
            ),
            trust_bundle=trust,
            transport=transport,
        )
        ctx = ExactByteContext(
            request_id="req-demo-1",
            observed_action=copy.deepcopy(action),
            observed_dispatch=copy.deepcopy(dispatch),
            decision_receipt_digest=Z,
            authority_receipt_digest=ONE,
            approval_artifact_digest=Z,
            state_snapshot_digest=Z,
            policy_bundle_digest=ONE,
            obligations_digest=Z,
            at_time=at,
        )

        print("1) ALLOW path — exact-byte dispatch")
        ok = dispatcher.dispatch(
            authorization=authorization,
            wire_bytes=WIRE,
            context=ctx,
            observed_at=at,
        )
        if not ok.sent or transport.writes != [WIRE] or ok.witness is None:
            _fail(f"happy path failed: sent={ok.sent} reason={ok.reason_code}")
        print("   sent exact bytes; witness created")

        print("2) Mutation after authorize — must refuse")
        transport.writes.clear()
        # Fresh EA bound to the honest WIRE; attempt send with mutated bytes.
        unsigned = {k: v for k, v in authorization.items() if k != "signature"}
        unsigned["execution_authorization_id"] = f"eauth-{uuid.uuid4()}"
        unsigned["nonce"] = uuid.uuid4().hex
        mut_auth = sign_execution_authorization(unsigned, runtime_key)
        tampered = WIRE.replace(b"400000", b"900000")
        mut = dispatcher.dispatch(
            authorization=mut_auth,
            wire_bytes=tampered,
            context=ctx,
            observed_at=at,
        )
        if mut.sent or transport.writes:
            _fail("mutation was sent")
        if mut.reason_code != "EXECUTION_AUTHORIZATION_NON_CONFORMANT":
            _fail(f"unexpected mutation reason: {mut.reason_code}")
        print("   refused; nothing sent")

        print("3) Replay consumed EA — must refuse")
        transport.writes.clear()
        replay = dispatcher.dispatch(
            authorization=authorization,
            wire_bytes=WIRE,
            context=ctx,
            observed_at=at,
        )
        if replay.sent or transport.writes:
            _fail("replay was sent")
        if replay.reason_code != EXECUTION_AUTHORIZATION_CONSUMED:
            _fail(f"unexpected replay reason: {replay.reason_code}")
        print("   refused as EXECUTION_AUTHORIZATION_CONSUMED")

        print("4) Offline independent witness verification")
        boundary = verify_dispatch_witness(
            ok.witness,
            authorization,
            trust,
            observed_action=action,
            observed_dispatch=dispatch,
            wire_bytes=WIRE,
            peer_identity_bytes=PEER,
        )
        if not boundary.ok:
            _fail(f"witness offline verify failed: {boundary.reason_code}")
        print("   verify_dispatch_witness OK")

        print()
        print(
            "OK — exact-byte adapter: allow / mutate-refuse / "
            "replay-refuse / offline witness"
        )


if __name__ == "__main__":
    main()
