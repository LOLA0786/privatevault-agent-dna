#!/usr/bin/env python3
"""
Independent verifier for decision/execution JSONL audit files.

Chain verification uses only the Python standard library and does not
import agent_dna. Trusted signature verification is optional and requires
PyNaCl, the same maintained Ed25519 implementation used by the signer.

Checks:
  1.  Every line is strict JSON (NaN/Infinity rejected).
  2.  Every record carries EXACTLY the DRP field set for its kind --
      unknown fields and missing fields both fail (a stripped-and-
      rehashed record is internally consistent; the field set is what
      catches it).
  3.  record_hash equals sha256 of the canonical payload (all fields
      except record_hash, sorted keys, compact separators), and both
      record_hash and prev_hash are 64 lowercase hex.
  4.  decision_id and event_id are unique file-wide (duplicates fail;
      references bind to the FIRST occurrence).
  5.  kind=="decision": per agent, in file order, prev_hash equals the
      previous decision's record_hash. The FIRST record of an agent
      establishes that agent's origin: 64 zeros = genesis, anything
      else = external provenance anchor (drp/0.1 anchor rule).
      Anchored agents are REPORTED -- the file proves continuity from
      the anchor; anchor authenticity is attested out of band.
  6.  Lineage: a non-null parent_decision must reference a decision
      seen EARLIER, belonging to the SAME agent, whose record_hash
      equals this record's prev_hash (i.e. the immediate prior
      decision), and exactly one "follows" edge must target it. A null
      parent_decision forbids "follows" edges.
  7.  Enums: decision in {allow, require_approval, block}; execution
      status in {ok, error, refused}.
  8.  kind=="execution": prev_hash equals the referenced decision's
      record_hash; the decision must appear earlier; the execution's
      agent_id must equal the decision's; at most one execution per
      decision; "resulted_in" edges must target decision_ref.
  9.  ENFORCEMENT DIVERGENCE: an execution with status "ok" whose
      decision was "block" fails -- the runtime refused and the world
      executed anyway.
  10. When detached envelopes and trusted keys are supplied, every decision
      must have exactly one valid Ed25519 envelope signed by a trusted key.

Exit codes: 0 pass, 1 fail, 2 usage.
Usage:
  python3 verify_records.py <records.jsonl>
  python3 verify_records.py <records.jsonl> \
      --envelopes <envelopes.jsonl> --trusted-key <public-key-hex>
"""

import argparse
import hashlib
import json
import re
import sys

GENESIS_HASH = "0" * 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

DECISION_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "decision_id",
        "parent_decision",
        "agent_id",
        "capability",
        "decision",
        "triggered_by",
        "reason",
        "severity",
        "drift_score",
        "evidence",
        "evidence_strength",
        "arguments_digest",
        "outcome",
        "request_id",
        "goal",
        "intent",
        "policy_id",
        "approval_ref",
        "receipt_ref",
        "edges",
        "timestamp",
        "prev_hash",
        "record_hash",
    }
)
EXECUTION_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "event_id",
        "agent_id",
        "decision_ref",
        "status",
        "detail",
        "edges",
        "timestamp",
        "prev_hash",
        "record_hash",
    }
)
DECISION_ENUM = {"allow", "require_approval", "block"}
STATUS_ENUM = {"ok", "error", "refused"}
ENVELOPE_FIELDS = frozenset(
    {
        "envelope_id",
        "algorithm",
        "signed_hash",
        "signature",
        "public_key",
        "key_id",
    }
)
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


def _reject_nonfinite(token):
    raise ValueError(f"non-finite number {token!r} is not valid JSON")


def compute_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _trusted_key(value: str) -> str:
    if not HEX64.match(value):
        raise argparse.ArgumentTypeError(
            "trusted keys must be 64 lowercase hexadecimal characters"
        )
    return value


def _verify_envelopes(  # noqa: C901 - ordered validation checklist
    path: str,
    trusted_keys: frozenset[str],
    decision_hashes: set[str],
) -> tuple[list[str], dict[str, int]]:
    failures = []
    stats = {
        "checked": 0,
        "valid": 0,
        "missing": 0,
        "invalid": 0,
        "untrusted": 0,
        "unexpected": 0,
    }

    try:
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        failures.append("trusted signature verification requires PyNaCl")
        return failures, stats

    seen_hashes = set()
    envelope_ids = set()

    with open(path, encoding="utf-8") as source:
        for lineno, line in enumerate(source, 1):
            line = line.strip()
            if not line:
                continue

            stats["checked"] += 1

            try:
                envelope = json.loads(
                    line,
                    parse_constant=_reject_nonfinite,
                )
            except ValueError as exc:
                failures.append(f"envelopes line {lineno}: invalid JSON ({exc})")
                stats["invalid"] += 1
                continue

            if not isinstance(envelope, dict):
                failures.append(f"envelopes line {lineno}: expected a JSON object")
                stats["invalid"] += 1
                continue

            unknown = set(envelope) - ENVELOPE_FIELDS
            missing = ENVELOPE_FIELDS - set(envelope)

            if unknown:
                failures.append(
                    f"envelopes line {lineno}: unknown field(s) {sorted(unknown)}"
                )
            if missing:
                failures.append(
                    f"envelopes line {lineno}: missing field(s) {sorted(missing)}"
                )
                stats["invalid"] += 1
                continue

            envelope_id = envelope["envelope_id"]
            if not isinstance(envelope_id, str) or not envelope_id:
                failures.append(f"envelopes line {lineno}: invalid envelope_id")
                stats["invalid"] += 1
            elif envelope_id in envelope_ids:
                failures.append(
                    f"envelopes line {lineno}: duplicate envelope_id {envelope_id!r}"
                )
                stats["invalid"] += 1
            else:
                envelope_ids.add(envelope_id)

            if envelope["algorithm"] != "Ed25519":
                failures.append(
                    f"envelopes line {lineno}: unsupported algorithm "
                    f"{envelope['algorithm']!r}"
                )
                stats["invalid"] += 1
                continue

            signed_hash = envelope["signed_hash"]
            if not isinstance(signed_hash, str) or not HEX64.match(signed_hash):
                failures.append(
                    f"envelopes line {lineno}: signed_hash is not 64 lowercase hex"
                )
                stats["invalid"] += 1
                continue

            if signed_hash in seen_hashes:
                failures.append(
                    f"envelopes line {lineno}: duplicate envelope for "
                    f"decision hash {signed_hash}"
                )
                stats["invalid"] += 1
                continue
            seen_hashes.add(signed_hash)

            if signed_hash not in decision_hashes:
                failures.append(
                    f"envelopes line {lineno}: envelope references "
                    f"unknown decision hash {signed_hash}"
                )
                stats["unexpected"] += 1
                continue

            public_key = envelope["public_key"]
            signature = envelope["signature"]

            if not isinstance(public_key, str) or not HEX64.match(public_key):
                failures.append(
                    f"envelopes line {lineno}: public_key is not 64 lowercase hex"
                )
                stats["invalid"] += 1
                continue

            if not isinstance(signature, str) or not HEX128.match(signature):
                failures.append(
                    f"envelopes line {lineno}: signature is not 128 lowercase hex"
                )
                stats["invalid"] += 1
                continue

            key_id = envelope["key_id"]
            if key_id is not None and not isinstance(key_id, str):
                failures.append(
                    f"envelopes line {lineno}: key_id must be a string or null"
                )
                stats["invalid"] += 1
                continue

            if public_key not in trusted_keys:
                failures.append(
                    f"envelopes line {lineno}: untrusted public key {public_key}"
                )
                stats["untrusted"] += 1
                continue

            try:
                VerifyKey(
                    public_key,
                    encoder=HexEncoder,
                ).verify(
                    signed_hash.encode(),
                    bytes.fromhex(signature),
                )
            except (BadSignatureError, ValueError):
                failures.append(f"envelopes line {lineno}: invalid Ed25519 signature")
                stats["invalid"] += 1
            else:
                stats["valid"] += 1

    missing_hashes = sorted(decision_hashes - seen_hashes)
    stats["missing"] = len(missing_hashes)

    for signed_hash in missing_hashes:
        failures.append(f"missing envelope for decision hash {signed_hash}")

    return failures, stats


def verify(  # noqa: C901 - mirrors the protocol check order
    path: str,
    *,
    envelopes_path: str | None = None,
    trusted_keys: frozenset[str] | None = None,
) -> int:
    failures = []
    chains = {}  # agent_id -> expected prev_hash (decisions)
    anchored = {}  # agent_id -> anchor hash (non-genesis origins)
    decisions = {}  # decision_id -> {"hash","decision","agent"} (first occurrence)
    decision_hashes = set()  # hashes requiring signature envelopes
    event_ids = set()
    executed = set()  # decision_ids with an execution event
    total = 0

    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1

            try:
                rec = json.loads(line, parse_constant=_reject_nonfinite)
            except ValueError as e:
                failures.append(f"line {lineno}: invalid JSON ({e})")
                continue

            pv = rec.get("protocol_version")
            if pv != "drp/0.1":
                failures.append(
                    f"line {lineno}: protocol_version {pv!r} is not drp/0.1"
                )

            kind = rec.get("kind", "decision")
            expected_fields = (
                DECISION_FIELDS
                if kind == "decision"
                else EXECUTION_FIELDS
                if kind == "execution"
                else None
            )
            if expected_fields is None:
                failures.append(f"line {lineno}: unknown kind {kind!r}")
                continue

            unknown = set(rec) - expected_fields
            missing = expected_fields - set(rec)
            if unknown:
                failures.append(f"line {lineno}: unknown field(s) {sorted(unknown)}")
            if missing:
                failures.append(f"line {lineno}: missing field(s) {sorted(missing)}")
                continue

            stored = rec.get("record_hash", "")
            prev = rec.get("prev_hash", "")
            for label, value in (("record_hash", stored), ("prev_hash", prev)):
                if not isinstance(value, str) or not HEX64.match(value):
                    failures.append(f"line {lineno}: {label} is not 64 lowercase hex")

            computed = compute_hash(rec)
            if stored != computed:
                failures.append(
                    f"line {lineno}: record_hash mismatch "
                    f"(stored {stored[:12]}.., computed {computed[:12]}..)"
                )

            if kind == "decision":
                if isinstance(stored, str) and HEX64.match(stored):
                    decision_hashes.add(stored)

                rid = rec.get("decision_id", f"<line {lineno}>")
                agent = rec.get("agent_id", "<missing>")

                if rec.get("decision") not in DECISION_ENUM:
                    failures.append(
                        f"line {lineno} [{rid}]: decision "
                        f"{rec.get('decision')!r} not in {sorted(DECISION_ENUM)}"
                    )

                if rid in decisions:
                    failures.append(
                        f"line {lineno} [{rid}]: duplicate decision_id "
                        "(references bind to the first occurrence)"
                    )
                    continue

                if agent in chains:
                    if prev != chains[agent]:
                        failures.append(
                            f"line {lineno} [{rid}]: chain break for agent {agent!r}"
                        )
                else:
                    # first record for this agent establishes the origin
                    if prev != GENESIS_HASH:
                        anchored[agent] = prev  # drp/0.1 anchor rule
                chains[agent] = stored

                # ---- lineage (P0-4) ----
                parent = rec.get("parent_decision")
                follows = [
                    e
                    for e in rec.get("edges", [])
                    if isinstance(e, dict) and e.get("type") == "follows"
                ]
                if parent is None:
                    if follows:
                        failures.append(
                            f"line {lineno} [{rid}]: follows edge present "
                            "but parent_decision is null"
                        )
                else:
                    pinfo = decisions.get(parent)
                    if pinfo is None:
                        failures.append(
                            f"line {lineno} [{rid}]: parent_decision "
                            f"{parent!r} does not reference an earlier "
                            "decision"
                        )
                    else:
                        if pinfo["agent"] != agent:
                            failures.append(
                                f"line {lineno} [{rid}]: parent_decision "
                                f"{parent!r} belongs to agent "
                                f"{pinfo['agent']!r}, not {agent!r}"
                            )
                        if pinfo["hash"] != prev:
                            failures.append(
                                f"line {lineno} [{rid}]: parent is not the "
                                "immediate prior decision (prev_hash != "
                                "parent record_hash)"
                            )
                    if len(follows) != 1 or follows[0].get("target") != parent:
                        failures.append(
                            f"line {lineno} [{rid}]: exactly one follows "
                            "edge targeting parent_decision is required"
                        )

                decisions[rid] = {
                    "hash": stored,
                    "decision": rec.get("decision"),
                    "agent": agent,
                }

            else:  # execution
                eid = rec.get("event_id", f"<line {lineno}>")
                dref = rec.get("decision_ref")

                if eid in event_ids:
                    failures.append(f"line {lineno} [{eid}]: duplicate event_id")
                event_ids.add(eid)

                if rec.get("status") not in STATUS_ENUM:
                    failures.append(
                        f"line {lineno} [{eid}]: status "
                        f"{rec.get('status')!r} not in {sorted(STATUS_ENUM)}"
                    )

                if dref not in decisions:
                    failures.append(
                        f"line {lineno} [{eid}]: execution references "
                        f"unknown/later decision {dref}"
                    )
                else:
                    dinfo = decisions[dref]
                    if prev != dinfo["hash"]:
                        failures.append(
                            f"line {lineno} [{eid}]: anchor mismatch — "
                            "prev_hash != decision record_hash"
                        )
                    if rec.get("agent_id") != dinfo["agent"]:
                        failures.append(
                            f"line {lineno} [{eid}]: execution agent_id "
                            f"{rec.get('agent_id')!r} != decision agent "
                            f"{dinfo['agent']!r}"
                        )
                    if dref in executed:
                        failures.append(
                            f"line {lineno} [{eid}]: duplicate execution "
                            f"event for decision {dref}"
                        )
                    executed.add(dref)

                    if dinfo["decision"] == "block" and rec.get("status") == "ok":
                        failures.append(
                            f"line {lineno} [{eid}]: ENFORCEMENT DIVERGENCE "
                            f"— decision {dref} was BLOCK but execution "
                            "status is ok"
                        )

                for edge in rec.get("edges", []):
                    if isinstance(edge, dict) and edge.get("type") == "resulted_in":
                        if edge.get("target") != dref:
                            failures.append(
                                f"line {lineno} [{eid}]: resulted_in edge "
                                "target != decision_ref"
                            )

    signature_stats = None
    if envelopes_path is not None:
        if not trusted_keys:
            failures.append("signature verification requires at least one trusted key")
        else:
            envelope_failures, signature_stats = _verify_envelopes(
                envelopes_path,
                trusted_keys,
                decision_hashes,
            )
            failures.extend(envelope_failures)

    print(f"records checked : {total}")
    print(f"agents          : {len(chains)}")
    print(
        f"anchored agents : {len(anchored)}"
        + (f" ({', '.join(sorted(anchored))})" if anchored else "")
    )
    print(f"decisions       : {len(decisions)}")
    print(f"executions      : {len(executed)}")
    if signature_stats is not None:
        print(f"envelopes checked: {signature_stats['checked']}")
        print(f"trusted keys    : {len(trusted_keys or ())}")
        print(f"valid envelopes : {signature_stats['valid']}")
        print(f"missing envelopes: {signature_stats['missing']}")
        print(f"invalid envelopes: {signature_stats['invalid']}")
        print(f"untrusted keys  : {signature_stats['untrusted']}")
        print(f"unexpected envs : {signature_stats['unexpected']}")
    print(f"failures        : {len(failures)}")
    for msg in failures:
        print(f"  FAIL {msg}")
    print("VERDICT:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a DRP audit record export.",
    )
    parser.add_argument("records", help="record JSONL export")
    parser.add_argument(
        "--envelopes",
        help="detached signature envelope JSONL export",
    )
    parser.add_argument(
        "--trusted-key",
        action="append",
        type=_trusted_key,
        default=[],
        help="trusted Ed25519 public key in hex; may be repeated",
    )
    args = parser.parse_args(argv)

    if bool(args.envelopes) != bool(args.trusted_key):
        parser.error("--envelopes and --trusted-key must be supplied together")

    return verify(
        args.records,
        envelopes_path=args.envelopes,
        trusted_keys=frozenset(args.trusted_key),
    )


if __name__ == "__main__":
    sys.exit(main())
