#!/usr/bin/env python3
"""A 2,400 USD customer refund, from authorisation to settlement evidence.

Observability reconstructs what an agent did after the fact. This refuses
before the bytes leave, and the refusal is provable to a third party who
does not trust the runtime that produced it.

Three records bind each other: the authorisation names the exact bytes a
service agent may send, an independent witness attests to what actually
crossed the wire, and the closure records what came back. The question
this answers is not "was the refund approved" -- a workflow engine can
approximate that. It is "were the bytes that reached the card network the
bytes somebody authorised, and can an auditor check that without us".

Run it, then read the attack section: the same refund, one field changed.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nacl.signing import SigningKey  # noqa: E402

from agent_dna.authority_v01 import (  # noqa: E402
    CANONICALIZATION,
    AuthorityFormatError,
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

# The refund instruction as it would actually be serialised for the
# processor. The authorisation commits to these exact bytes.
WIRE_BYTES = (
    b'{"type":"refund","case":"CASE-40218","account":"CUST-88213",'
    b'"amount_minor":240000,"currency":"USD","reason":"order_cancelled"}'
)
PEER_BYTES = b"refunds.cardnetwork.example:443"

GRANT_CAP_MINOR = 500000  # 5,000.00 USD standing authority for this agent
REFUND_MINOR = 240000  # 2,400.00 USD this case


def usd(minor: int) -> str:
    return f"{minor / 100:,.2f} USD"


def world() -> dict:
    """Keys, trust bundle, and the authorisation the runtime issued."""
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    closure_key = SigningKey.generate()

    trust_bundle = {
        "spec": "pv-trust-bundle/0.1-experimental",
        "canonicalization": CANONICALIZATION,
        "organisation_id": "retail.example",
        "bundle_version": 1,
        "pinned_at": "2026-08-05T09:00:00Z",
        "keys": [
            {
                "key_id": "pv-runtime-01",
                "principal": "decision-runtime@retail.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                # A DIFFERENT principal holding a DIFFERENT key. This is
                # what makes the witness worth anything: the runtime
                # cannot attest to its own egress.
                "key_id": "egress-witness-01",
                "principal": "refund-egress@retail.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer"],
            },
            {
                "key_id": "settlement-recorder-01",
                "principal": "refund-ops@retail.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(closure_key),
                "usages": ["closure_signer"],
            },
        ],
    }

    action = {
        "subject_principal": "service-agent@retail.example",
        "subject_key_id": "service-agent-07",
        "action": "refunds.issue",
        "resource": "account:CUST-88213",
        "parameters": {
            "amount": {"minor_units": REFUND_MINOR, "currency": "USD"},
            "case": "CASE-40218",
            "reason": "order_cancelled",
        },
    }

    dispatch = {
        "transport": "https",
        "destination": "refunds.cardnetwork.example",
        "operation": "POST /v2/refunds",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "refunds.cardnetwork.v2",
        "tool_schema_digest": ZERO,
        "tool_artifact_digest": ONE,
        "credential_audience": "refunds.cardnetwork.example",
        "idempotency_key_digest": ZERO,
        "retry_policy_digest": ONE,
    }

    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": "exec-auth-40218",
            "organisation_id": "retail.example",
            "request_id": "refund-request-40218",
            "issued_at": "2026-08-05T11:02:00Z",
            "not_before": "2026-08-05T11:02:00Z",
            "expires_at": "2026-08-05T11:07:00Z",
            "nonce": "exec-nonce-40218-cust-88213",
            "decision_receipt_digest": ZERO,
            "authority_receipt_digest": ONE,
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
            # Single use. Replaying it is not a retry, it is a second refund.
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
            "dispatch_witness_id": "egress-witness-40218",
            "observed_at": "2026-08-05T11:02:18Z",
            "attempt": 1,
            "witness_component_id": "refund-egress-01",
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
        "closure_id": "closure-40218",
        "organisation_id": auth["organisation_id"],
        "request_id": auth["request_id"],
        "execution_authorization_id": auth["execution_authorization_id"],
        "execution_authorization_digest": execution_authorization_digest(auth),
        "dispatch_witness_id": witness["dispatch_witness_id"],
        "dispatch_witness_digest": dispatch_witness_digest(witness),
        "closed_at": "2026-08-05T11:02:26Z",
        "closure_component_id": "settlement-recorder-01",
        "dispatch_outcome": "ACKNOWLEDGED",
        "response_status": "202",
        "response_bytes_digest": sha256_bytes_digest(b'{"status":"accepted"}'),
        "response_bytes_length": 21,
        # The network accepted the instruction. The money has not landed
        # in the customer's account yet, and the record does not pretend
        # it has.
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
) -> str:
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
        observed_action=observed_action if observed_action is not None else w["action"],
        observed_dispatch=w["dispatch"],
        wire_bytes=wire_bytes,
        peer_identity_bytes=PEER_BYTES,
    )

    if boundary.decision_conformance is not DecisionConformance.CONFORMANT:
        mark = _mark(boundary)
        print(f"  [{mark}] {label}")
        _show("boundary", boundary)
        print("         chain     not evaluated, upstream evidence failed")
        return mark.strip()

    chain = verify_closure_chain(authorization, witness, closure, w["trust_bundle"])
    mark = _mark(chain)
    print(f"  [{mark}] {label}")
    _show("boundary", boundary)
    _show("chain", chain)
    return mark.strip()


def main() -> int:
    print(RULE)
    print(f"CUSTOMER REFUND  {usd(REFUND_MINOR)}  ->  account CUST-88213")
    print(RULE)
    print("Agent      service-agent@retail.example")
    print("Case       CASE-40218")
    print(f"Authority  refunds.issue, standing cap {usd(GRANT_CAP_MINOR)}")
    print(
        f"Wire bytes {len(WIRE_BYTES)} bytes, digest "
        f"{sha256_bytes_digest(WIRE_BYTES)[:24]}..."
    )
    print()

    w = world()
    witness = witness_for(w)
    closure = closure_for(w, witness)

    print("THE HONEST CHAIN")
    print(THIN)
    print(
        f"  authorization  {execution_authorization_digest(w['authorization'])[:30]}..."
    )
    print(f"  witness        {dispatch_witness_digest(witness)[:30]}...")
    print("  each record names the digest of the one before it")
    print()

    outcomes = {}
    outcomes["clean"] = report(
        "refund dispatched as authorised", w, w["authorization"], witness, closure
    )

    print()
    print("THE SAME REFUND, ONE FIELD CHANGED")
    print(THIN)

    # 1. The agent inflates the amount after authorisation.
    inflated = copy.deepcopy(w["action"])
    inflated["parameters"]["amount"]["minor_units"] = 2400000  # 24,000.00
    outcomes["inflated"] = report(
        f"amount raised to {usd(2400000)} after authorisation",
        w,
        w["authorization"],
        witness,
        closure,
        observed_action=inflated,
    )

    # 2. One byte of the instruction differs from what was authorised.
    tampered_bytes = WIRE_BYTES.replace(
        b'"amount_minor":240000', b'"amount_minor":240009'
    )
    tampered_witness = witness_for(w, wire_bytes=tampered_bytes)
    outcomes["wire"] = report(
        "one byte of the refund instruction changed in flight",
        w,
        w["authorization"],
        tampered_witness,
        closure,
        wire_bytes=tampered_bytes,
    )

    # 3. The authorisation is presented a second time. This one never
    # reaches a verifier: a closure claiming a second use of a
    # single-use permit cannot be constructed, let alone signed.
    try:
        closure_for(w, witness, authorization_use_count=2)
        outcomes["replay"] = "ACCEPTED"
        print("  [ACCEPTED] second use of a single-use authorisation")
    except AuthorityFormatError as exc:
        outcomes["replay"] = "REFUSED"
        print("  [REFUSED ] single-use authorisation replayed for a second refund")
        print(f"         construct {exc}")
        print("         the record cannot be built, so there is nothing to sign")

    # 4. The closure claims the money reached the customer. Nothing
    # attests to that. Like the replay, this is refused at construction:
    # the format does not permit an unevidenced settlement claim.
    try:
        closure_for(w, witness, effect_state="CONFIRMED")
        outcomes["overclaim"] = "ACCEPTED"
        print("  [ACCEPTED] settlement claimed without evidence")
    except AuthorityFormatError as exc:
        outcomes["overclaim"] = "REFUSED"
        print("  [REFUSED ] closure claims settlement it cannot evidence")
        print(f"         construct {exc}")
        print("         ACKNOWLEDGED and CONFIRMED are different claims,")
        print("         and only one of them is free")

    print()
    print(THIN)
    accepted = [k for k, v in outcomes.items() if v == "ACCEPTED"]
    print(f"  accepted: {accepted}")
    print("  Every refusal above is a signed artifact. An auditor re-runs")
    print("  these checks with the trust bundle and the three records, and")
    print("  needs nothing from the runtime that produced them.")
    print(RULE)

    return 0 if accepted == ["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
