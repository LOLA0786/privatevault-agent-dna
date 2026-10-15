#!/usr/bin/env python3
"""Independent verifier for an exported multi-agent flow (ADR 0021).

Input: the JSON body of ``GET /v1/flows/{flow_id}``. Deliberately does not
import ``agent_dna``: an auditor checks the runtime's evidence without
trusting the runtime's code. Standard library only, plus PyNaCl when
signatures are checked.

Checks, in order:
  1.  The file is one JSON object, no duplicate keys, no NaN/Infinity.
  2.  At least one event; every event is sealed (no pre-PR-3 rows).
  3.  Each event has exactly the pv-lineage-event/0.1 fields and the
      export's flow_id.
  4.  event_hash == sha256("pv-lineage-event/0.1\\n" + canonical JSON).
  5.  seq runs 1..n without gaps; prev_event_hash chains from 64 zeros.
  6.  Dual control: every approval names an initiate earlier in this flow,
      made by a different agent; at most one ALLOWed approval per initiate.
  7.  With --trusted-key: every event carries an Ed25519 envelope from a
      trusted key over its event_hash.

Exit codes: 0 pass, 1 fail, 2 usage.
Usage:
  python3 verify_lineage.py flow.json
  python3 verify_lineage.py flow.json --trusted-key <public-key-hex>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

SPEC = "pv-lineage-event/0.1"
DOMAIN = b"pv-lineage-event/0.1\n"
GENESIS = "0" * 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EVENT_FIELDS = frozenset(
    {
        "spec",
        "flow_id",
        "seq",
        "prev_event_hash",
        "record_hash",
        "decision_id",
        "agent",
        "capability",
        "intent",
        "decision",
        "parent_record_hash",
        "approves_record_hash",
        "occurred_at",
    }
)
INTENTS = frozenset({"initiate", "approve", "other"})
DECISIONS = frozenset({"allow", "require_approval", "block"})


def _reject_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(token):
    raise ValueError(f"non-finite number {token!r}")


def event_hash(event: dict) -> str:
    body = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(DOMAIN + body.encode("utf-8")).hexdigest()


def _check_event_shape(i: int, event, flow_id: str, failures: list[str]) -> bool:
    if not isinstance(event, dict):
        failures.append(f"event {i}: not sealed (recorded before lineage evidence)")
        return False
    missing, extra = EVENT_FIELDS - set(event), set(event) - EVENT_FIELDS
    if missing or extra:
        failures.append(
            f"event {i}: field set mismatch (missing {sorted(missing)}, "
            f"unexpected {sorted(extra)})"
        )
        return False
    if event["spec"] != SPEC:
        failures.append(f"event {i}: spec {event['spec']!r} != {SPEC!r}")
    if event["flow_id"] != flow_id:
        failures.append(f"event {i}: flow_id differs from the export's")
    if event["intent"] not in INTENTS:
        failures.append(f"event {i}: intent {event['intent']!r} invalid")
    if event["decision"] not in DECISIONS:
        failures.append(f"event {i}: decision {event['decision']!r} invalid")
    if not isinstance(event["record_hash"], str) or not HEX64.match(
        event["record_hash"]
    ):
        failures.append(f"event {i}: record_hash is not 64 lowercase hex")
    return True


def _check_signature(i, item, digest, trusted, failures) -> None:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    env = item.get("envelope")
    if not isinstance(env, dict):
        failures.append(f"event {i}: missing signature envelope")
        return
    if env.get("algorithm") != "Ed25519":
        failures.append(f"event {i}: unsupported algorithm {env.get('algorithm')!r}")
        return
    if env.get("signed_hash") != digest:
        failures.append(f"event {i}: envelope signs a different hash")
        return
    public_key = str(env.get("public_key", "")).lower()
    if public_key not in trusted:
        failures.append(f"event {i}: untrusted public key {public_key}")
        return
    try:
        VerifyKey(bytes.fromhex(public_key)).verify(
            digest.encode(), bytes.fromhex(str(env.get("signature", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append(f"event {i}: invalid Ed25519 signature")


def verify(  # noqa: C901 - ordered checklist, mirrors verify_records.py
    document: dict, trusted: frozenset[str] | None
) -> list[str]:
    failures: list[str] = []
    flow_id = document.get("flow_id")
    items = document.get("events")
    if not isinstance(flow_id, str) or not isinstance(items, list):
        return ["export must be an object with string flow_id and list events"]
    if not items:
        return ["export contains no events"]

    initiates: dict[str, str] = {}  # record_hash -> agent
    approved: set[str] = set()
    expected_prev = GENESIS
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict):
            failures.append(f"event {i}: not an object")
            continue
        event = item.get("event")
        if not _check_event_shape(i, event, flow_id, failures):
            continue
        digest = event_hash(event)
        if item.get("event_hash") != digest:
            failures.append(f"event {i}: event_hash does not match its content")
        if event["seq"] != i:
            failures.append(f"event {i}: seq {event['seq']} (expected {i})")
        if event["prev_event_hash"] != expected_prev:
            failures.append(f"event {i}: chain broken (prev_event_hash mismatch)")
        expected_prev = digest
        if trusted is not None:
            _check_signature(i, item, digest, trusted, failures)

        if event["intent"] == "initiate":
            initiates[event["record_hash"]] = event["agent"]
        approves = event["approves_record_hash"]
        if event["intent"] == "approve" and approves is not None:
            maker = initiates.get(approves)
            if maker is None:
                failures.append(
                    f"event {i}: approves a decision that is not an earlier "
                    "initiate in this flow"
                )
            elif maker == event["agent"]:
                failures.append(
                    f"event {i}: DUAL CONTROL VIOLATION, {maker} approved "
                    "its own initiate"
                )
            if event["decision"] == "allow":
                if approves in approved:
                    failures.append(
                        f"event {i}: DUAL CONTROL VIOLATION, initiate approved "
                        "more than once"
                    )
                approved.add(approves)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an exported lineage flow.")
    parser.add_argument("flow", help="JSON body of GET /v1/flows/{flow_id}")
    parser.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        help="trusted Ed25519 public key (hex); may be repeated",
    )
    args = parser.parse_args(argv)
    for key in args.trusted_key:
        if not HEX64.match(key.lower()):
            parser.error("trusted keys must be 64 hexadecimal characters")
    try:
        with open(args.flow, encoding="utf-8") as fh:
            document = json.load(
                fh,
                object_pairs_hook=_reject_duplicates,
                parse_constant=_reject_constant,
            )
    except (OSError, ValueError) as exc:
        print(f"FAIL unreadable export: {exc}")
        print("VERDICT: FAIL")
        return 1
    if not isinstance(document, dict):
        print("FAIL export is not a JSON object")
        print("VERDICT: FAIL")
        return 1
    trusted = (
        frozenset(k.lower() for k in args.trusted_key) if args.trusted_key else None
    )
    failures = verify(document, trusted)
    events = document.get("events")
    print(f"flow            : {document.get('flow_id')}")
    print(f"events checked  : {len(events) if isinstance(events, list) else 0}")
    print(f"signatures      : {'checked' if trusted else 'not checked'}")
    for message in failures:
        print(f"  FAIL {message}")
    print("VERDICT:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
