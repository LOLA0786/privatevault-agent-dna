#!/usr/bin/env python3
"""A 25 crore supplier payment, from authorisation to settlement evidence.

Five records, each binding the one before it. The question this answers is
not "was the payment authorised" -- most systems can approximate that. It
is "were the bytes that crossed the wire the bytes somebody authorised,
and can a third party check that without trusting us".

Run it. Then read the attack section, where the same chain is presented
with one field changed.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nacl.signing import SigningKey  # noqa: E402

from agent_dna.authority_v01 import (  # noqa: E402
    CANONICALIZATION,
    DecisionConformance,
    EvidenceState,
    encode_public_key,
    sha256_digest,
)
from agent_dna.closure_v01 import (  # noqa: E402
    CLOSURE_RECORD_SPEC,
    sign_closure_record,
    verify_closure_chain,
)
from agent_dna.dispatch_v01 import (  # noqa: E402
    create_dispatch_witness,
    dispatch_witness_digest,
    verify_dispatch_witness,
)
from agent_dna.execution_v01 import (  # noqa: E402
    EXECUTION_AUTHORIZATION_SPEC,
    execution_authorization_digest,
    sha256_bytes_digest,
    sign_execution_authorization,
)

RULE = "=" * 74
THIN = "-" * 74
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64

# The exact bytes the payment rail will receive. Everything downstream
# binds to these, not to a description of them.
WIRE_BYTES = (
    b'{"debit":"CORP-A-8841","credit":"TATA-PROJ-4471",'
    b'"amount":{"minor_units":25000000000,"currency":"INR"},'
    b'"rail":"RTGS","beneficiary_bank":"HDFC","purpose":"INV-8841"}'
)
PEER_BYTES = b"CN=rtgs.hdfcbank.example,O=HDFC Bank"


def world() -> dict:
    """Keys, trust bundle and the authorisation the treasury head issued."""
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    closure_key = SigningKey.generate()

    trust_bundle = {
        "spec": "pv-trust-bundle/0.1-experimental",
        "canonicalization": CANONICALIZATION,
        "organisation_id": "bank.example",
        "bundle_version": 1,
        "pinned_at": "2026-07-31T09:00:00Z",
        "keys": [
            {
                "key_id": "pv-runtime-01",
                "principal": "decision-runtime@bank.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "egress-witness-01",
                "principal": "payment-egress@bank.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer"],
            },
            {
                "key_id": "settlement-recorder-01",
                "principal": "settlement-ops@bank.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(closure_key),
                "usages": ["closure_signer"],
            },
        ],
    }

    action = {
        "subject_principal": "treasury-agent@bank.example",
        "subject_key_id": "treasury-agent-02",
        "action": "payments.execute",
        "resource": "supplier:TATA-PROJ-4471",
        "parameters": {
            "amount": {"minor_units": 25000000000, "currency": "INR"},
            "rail": "RTGS",
            "invoice": "INV-8841",
        },
    }

    dispatch = {
        "transport": "https",
        "destination": "rtgs.hdfcbank.example",
        "operation": "POST /v1/payments",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.rtgs.v2",
        "tool_schema_digest": ZERO,
        "tool_artifact_digest": ONE,
        "credential_audience": "rtgs.hdfcbank.example",
        "idempotency_key_digest": ZERO,
        "retry_policy_digest": ONE,
    }

    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": "exec-auth-8841",
            "organisation_id": "bank.example",
            "request_id": "payment-request-8841",
            "issued_at": "2026-07-31T09:14:00Z",
            "not_before": "2026-07-31T09:14:00Z",
            "expires_at": "2026-07-31T09:19:00Z",
            "nonce": "exec-nonce-8841-inv-8841-rtgs",
            "decision_receipt_digest": ZERO,
            "authority_receipt_digest": ONE,
            # In deployment this is the digest of the maker/checker
            # approval artifact, which binds the evidence they saw.
            "approval_artifact_digest": ZERO,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(WIRE_BYTES),
            "expected_wire_bytes_length": len(WIRE_BYTES),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER_BYTES),
            "dispatch": dispatch,
            "state_snapshot_digest": ZERO,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": ONE,
            "max_uses": 1,
            "signer_key_id": "pv-runtime-01",
        },
        runtime_key,
    )

    return {
        "trust_bundle": trust_bundle,
        "authorization": authorization,
        "runtime_key": runtime_key,
        "action": copy.deepcopy(action),
        "dispatch": copy.deepcopy(dispatch),
        "witness_key": witness_key,
        "closure_key": closure_key,
    }


def witness_for(w: dict, *, wire_bytes: bytes = WIRE_BYTES, action=None) -> dict:
    return create_dispatch_witness(
        {
            "dispatch_witness_id": "egress-witness-8841",
            "observed_at": "2026-07-31T09:14:22Z",
            "attempt": 1,
            "witness_component_id": "payment-egress-01",
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "signer_key_id": "egress-witness-01",
        },
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        observed_action=action if action is not None else w["action"],
        observed_dispatch=w["dispatch"],
        wire_bytes=wire_bytes,
        peer_identity_bytes=PEER_BYTES,
        signing_key=w["witness_key"],
    )


def closure_for(w: dict, witness: dict, **overrides) -> dict:
    auth = w["authorization"]
    closure = {
        "spec": CLOSURE_RECORD_SPEC,
        "canonicalization": CANONICALIZATION,
        "closure_id": "closure-8841",
        "organisation_id": auth["organisation_id"],
        "request_id": auth["request_id"],
        "execution_authorization_id": auth["execution_authorization_id"],
        "execution_authorization_digest": execution_authorization_digest(auth),
        "dispatch_witness_id": witness["dispatch_witness_id"],
        "dispatch_witness_digest": dispatch_witness_digest(witness),
        "closed_at": "2026-07-31T09:14:31Z",
        "closure_component_id": "settlement-recorder-01",
        "dispatch_outcome": "ACKNOWLEDGED",
        "response_status": "202",
        "response_bytes_digest": sha256_bytes_digest(b'{"status":"accepted"}'),
        "response_bytes_length": 21,
        # The bank acknowledged the instruction. It has not confirmed
        # settlement, and the record does not pretend otherwise.
        "effect_state": "UNCONFIRMED",
        "effect_evidence_digest": None,
        "idempotency_key_digest": auth["dispatch"]["idempotency_key_digest"],
        "authorization_use_count": 1,
        "trust_bundle_digest": auth["trust_bundle_digest"],
        "signer_key_id": "settlement-recorder-01",
    }
    closure.update(overrides)
    return sign_closure_record(closure, w["closure_key"])


def _mark(result) -> str:
    if result.decision_conformance is DecisionConformance.CONFORMANT:
        return "ACCEPTED"
    if result.evidence_state is EvidenceState.VERIFIED:
        # The evidence is sound and the claim it makes is false. That is
        # the finding, not a failure of the check.
        return "REFUSED "
    return "INVALID "


def _show(stage: str, result) -> None:
    print(
        f"         {stage:9} {result.evidence_state.value} / "
        f"{result.decision_conformance.value}"
    )
    for failure in result.failures:
        print(f"           - {failure}")


def report(
    label: str,
    w: dict,
    authorization,
    witness,
    closure,
    *,
    observed_action=None,
    wire_bytes: bytes = WIRE_BYTES,
) -> None:
    """Verify in the order a real deployment would.

    The witness answers whether the dispatched bytes were the authorised
    bytes. The chain answers whether the closure is about that execution.
    If the first fails there is nothing useful the second can say, so it
    is not evaluated -- which is also how the standalone verifier walks
    the records.
    """

    boundary = verify_dispatch_witness(
        witness,
        authorization,
        w["trust_bundle"],
        observed_action=observed_action
        if observed_action is not None
        else w["action"],
        observed_dispatch=w["dispatch"],
        wire_bytes=wire_bytes,
        peer_identity_bytes=PEER_BYTES,
    )

    if boundary.decision_conformance is not DecisionConformance.CONFORMANT:
        print(f"  [{_mark(boundary)}] {label}")
        _show("boundary", boundary)
        print("         chain     not evaluated, upstream evidence failed")
        return

    chain = verify_closure_chain(
        authorization, witness, closure, w["trust_bundle"]
    )
    print(f"  [{_mark(chain)}] {label}")
    _show("boundary", boundary)
    _show("chain", chain)


def main() -> int:
    print(RULE)
    print("SUPPLIER PAYMENT  25,00,00,000 INR  ->  Tata Projects, via RTGS")
    print(RULE)
    print("Agent      treasury-agent@bank.example")
    print("Invoice    INV-8841")
    print(f"Wire bytes {len(WIRE_BYTES)} bytes, digest "
          f"{sha256_bytes_digest(WIRE_BYTES)[:24]}...")
    print()

    w = world()
    witness = witness_for(w)
    closure = closure_for(w, witness)

    print("THE HONEST CHAIN")
    print(THIN)
    print(f"  authorization  {execution_authorization_digest(w['authorization'])[:30]}...")
    print(f"  witness        {dispatch_witness_digest(witness)[:30]}...")
    print("  closure        binds both, signed by a distinct key")
    print()
    report("exact authorised payment, dispatched once", w,
           w["authorization"], witness, closure)

    print()
    print("THE SAME CHAIN, ONE FIELD CHANGED")
    print(THIN)

    # 1. amount inflated after authorisation
    tampered_action = copy.deepcopy(w["action"])
    tampered_action["parameters"]["amount"]["minor_units"] = 250000000000
    try:
        bad_witness = witness_for(w, action=tampered_action)
        report("amount changed to 250 crore after authorisation", w,
               w["authorization"], bad_witness, closure,
               observed_action=tampered_action)
    except Exception as exc:
        print("  [REFUSED ] amount changed to 250 crore after authorisation")
        print(f"         refused at witness creation: {type(exc).__name__}")

    # 2. different bytes on the wire
    try:
        swapped = witness_for(w, wire_bytes=b'{"credit":"ATTACKER-ACCOUNT"}')
        report("different bytes presented for dispatch", w,
               w["authorization"], swapped, closure,
               wire_bytes=b'{"credit":"ATTACKER-ACCOUNT"}')
    except Exception as exc:
        print("  [REFUSED ] different bytes presented for dispatch")
        print(f"         refused at witness creation: {type(exc).__name__}")

    # 3. a second legitimate payment in the same organisation, under the
    #    same trust roots. The closure from the first is presented against
    #    it. Both authorisations are validly signed; the closure is simply
    #    about the wrong one.
    second = copy.deepcopy(w["authorization"])
    second = {k: v for k, v in second.items() if k != "signature"}
    second["execution_authorization_id"] = "exec-auth-8842"
    second["request_id"] = "payment-request-8842"
    second["nonce"] = "exec-nonce-8842-inv-8842-rtgs"
    second = sign_execution_authorization(second, w["runtime_key"])

    report("closure from one payment presented against another", w,
           second, witness, closure)

    # 4. settlement claimed without evidence
    try:
        closure_for(w, witness, effect_state="CONFIRMED")
        print("  [ACCEPTED] settlement claimed with no evidence -- BUG")
    except Exception as exc:
        print("  [REFUSED ] settlement claimed with no evidence")
        print(f"         refused at signing: {str(exc)[:60]}")

    print()
    print(RULE)
    print("WHAT A THIRD PARTY CAN CHECK")
    print(THIN)
    print("  Every digest above is recomputed from the documents, not taken")
    print("  on trust. The closure is signed by a key that is not the key")
    print("  that authorised the payment, so one compromised component")
    print("  cannot produce a complete and consistent fiction.")
    print()
    print("  The bank acknowledged the instruction. The record says")
    print("  UNCONFIRMED, because an acknowledgement is not settlement.")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
