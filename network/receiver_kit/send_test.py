"""Send three requests through the gate from outside and check what happened.

1. A valid permit for one transfer: expect 200, and the upstream sees exactly
   that body once, without the permit header.
2. The same permit with the amount changed in the body: expect 403
   RECEIVER_WIRE_MISMATCH, and the upstream sees nothing new.
3. The first request replayed byte for byte: expect 409
   RECEIVER_PERMIT_CONSUMED, and the upstream sees nothing new.

The permit is signed locally with the demo issuer key (``keygen.py issuer``)
using ``agent_dna.execution_v01.sign_execution_authorization``. The real
``/v1/decide`` and ``/v1/authorize`` path is the issuer quickstart (Phase 3).

Exit status is 0 only if all three behave.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import CANONICALIZATION, encode_public_key, sha256_digest
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.wire_serialization_v01 import serialize_parameters_wire
from network.receiver_kit.config import (
    ConfigError,
    load_signing_key,
    parse_issuer_keys,
    trust_bundle,
)

SERIALIZATION = "pv-json-parameters/0.1"
OPERATION = "POST /api/v1/transfers"
PATH = "/api/v1/transfers"
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64

PARAMETERS: dict[str, Any] = {
    "fromAccountId": "A-1001",
    "toAccountId": "B-2002",
    "amount": 5000,
    "currency": "USD",
}
TAMPERED: dict[str, Any] = {**PARAMETERS, "amount": 50000}

# send(method, path, headers, body) -> (status, headers, body)
Sender = Callable[
    [str, str, Mapping[str, str], bytes], tuple[int, Mapping[str, str], bytes]
]
# seen() -> records the upstream has received so far
Seen = Callable[[], list[dict[str, Any]]]


@dataclass(frozen=True)
class Issuer:
    signing_key: SigningKey
    key_id: str
    organisation_id: str
    bundle: dict[str, Any]
    receiver_id: str
    destination: str


def mint_permit(
    issuer: Issuer,
    parameters: Mapping[str, Any],
    *,
    now: datetime | None = None,
    ttl_s: int = 60,
) -> tuple[dict[str, Any], bytes]:
    """Sign a permit bound to ``parameters``; return (permit, wire bytes)."""
    moment = (now or datetime.now(UTC)).replace(microsecond=0)
    wire = serialize_parameters_wire(dict(parameters), serialization=SERIALIZATION)
    action = {
        "subject_principal": f"payments-agent@{issuer.organisation_id}",
        "subject_key_id": "payments-agent",
        "action": "payments.transfer",
        "resource": f"account:{parameters['fromAccountId']}",
        "parameters": dict(parameters),
    }
    dispatch = {
        "transport": "https",
        "destination": issuer.destination,
        "operation": OPERATION,
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.transfers.v1",
        "tool_schema_digest": ZERO,
        "tool_artifact_digest": ONE,
        "credential_audience": issuer.receiver_id,
        "idempotency_key_digest": ZERO,
        "retry_policy_digest": ONE,
        "serialization": SERIALIZATION,
    }
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    # not_before sits a few seconds in the past so a small clock difference
    # between this machine and the gate does not refuse a fresh permit; the
    # schema requires issued_at <= not_before.
    not_before = moment - timedelta(seconds=5)
    permit = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": f"eauth-{uuid.uuid4()}",
            "organisation_id": issuer.organisation_id,
            "request_id": f"req-{uuid.uuid4().hex[:8]}",
            "issued_at": not_before.strftime(stamp),
            "not_before": not_before.strftime(stamp),
            "expires_at": (moment + timedelta(seconds=ttl_s)).strftime(stamp),
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": ZERO,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": ZERO,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(wire),
            "expected_wire_bytes_length": len(wire),
            "expected_peer_identity_digest": sha256_bytes_digest(
                f"tls-spki:{issuer.receiver_id}".encode()
            ),
            "dispatch": dispatch,
            "state_snapshot_digest": ZERO,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(issuer.bundle),
            "obligations_digest": ZERO,
            "max_uses": 1,
            "signer_key_id": issuer.key_id,
        },
        issuer.signing_key,
    )
    return permit, wire


@dataclass
class Step:
    name: str
    expect_status: int
    expect_reason: str | None
    status: int = 0
    reason: str | None = None
    upstream_before: int = 0
    upstream_after: int = 0
    expect_upstream_delta: int = 0
    note: str = ""

    @property
    def ok(self) -> bool:
        return (
            self.status == self.expect_status
            and self.reason == self.expect_reason
            and self.upstream_after - self.upstream_before == self.expect_upstream_delta
            and not self.note.startswith("FAIL")
        )


def _reason(body: bytes) -> str | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return payload.get("reason_code") if isinstance(payload, dict) else None


def run(issuer: Issuer, send: Sender, seen: Seen) -> list[Step]:
    permit, wire = mint_permit(issuer, PARAMETERS)
    headers = {
        "Content-Type": "application/json",
        PERMIT_HEADER: encode_permit_header(permit),
    }
    tampered = serialize_parameters_wire(TAMPERED, serialization=SERIALIZATION)
    steps: list[Step] = []

    # 1. valid permit
    step = Step("valid permit", 200, None, expect_upstream_delta=1)
    step.upstream_before = len(seen())
    step.status, resp_headers, body = send("POST", PATH, headers, wire)
    step.reason = _reason(body) if step.status != 200 else None
    records = seen()
    step.upstream_after = len(records)
    if step.status == 200:
        last = records[-1] if records else {}
        if last.get("body_sha256") != "sha256:" + hashlib.sha256(wire).hexdigest():
            step.note = "FAIL upstream did not receive the exact bound bytes"
        elif PERMIT_HEADER.lower() in last.get("header_names", []):
            step.note = "FAIL permit header was forwarded to the upstream"
        elif not any(k.lower() == "x-pv-receiver-receipt" for k in resp_headers):
            step.note = "FAIL no receipt digest header on the admitted response"
        else:
            step.note = "upstream saw it once, permit header stripped, receipt returned"
    steps.append(step)

    # 2. amount changed after approval, same permit
    step = Step("amount changed", 403, "RECEIVER_WIRE_MISMATCH")
    step.upstream_before = len(seen())
    step.status, _, body = send("POST", PATH, headers, tampered)
    step.reason = _reason(body)
    step.upstream_after = len(seen())
    step.note = "upstream never saw the altered body"
    steps.append(step)

    # 3. replay of the first request
    step = Step("replay", 409, "RECEIVER_PERMIT_CONSUMED")
    step.upstream_before = len(seen())
    step.status, _, body = send("POST", PATH, headers, wire)
    step.reason = _reason(body)
    step.upstream_after = len(seen())
    step.note = "permit already consumed; upstream saw nothing new"
    steps.append(step)
    return steps


def report(steps: list[Step]) -> str:
    width = max(len(s.name) for s in steps)
    lines = []
    for s in steps:
        mark = "PASS" if s.ok else "FAIL"
        got = f"{s.status} {s.reason or ''}".strip()
        want = f"{s.expect_status} {s.expect_reason or ''}".strip()
        delta = s.upstream_after - s.upstream_before
        lines.append(
            f"{mark}  {s.name.ljust(width)}  got {got:<32} want {want:<32} "
            f"upstream +{delta}  {s.note}"
        )
    lines.append("ALL PASS" if all(s.ok for s in steps) else "SOME FAILED")
    return "\n".join(lines)


def exit_code(steps: list[Step]) -> int:
    return 0 if steps and all(s.ok for s in steps) else 1


# ----------------------------------------------------------------- CLI wiring


def read_env_file(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE reader for the kit's .env (no interpolation)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def urllib_sender(base_url: str) -> Sender:
    def send(
        method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        request = urllib.request.Request(
            base_url.rstrip("/") + path, data=body, method=method, headers=dict(headers)
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers.items()), err.read()

    return send


def urllib_seen(upstream_url: str) -> Seen:
    def seen() -> list[dict[str, Any]]:
        with urllib.request.urlopen(
            upstream_url.rstrip("/") + "/_seen", timeout=10
        ) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return list(data) if isinstance(data, list) else []

    return seen


def issuer_from(
    env: Mapping[str, str], *, issuer_key_file: Path, issuer_key_id: str
) -> Issuer:
    def need(name: str) -> str:
        value = env.get(name, "").strip()
        if not value:
            raise ConfigError(f"{name} is required (set it in .env or the environment)")
        return value

    keys = parse_issuer_keys(need("PV_ISSUER_KEYS"))
    organisation = need("PV_ISSUER_ORGANISATION")
    signing_key = load_signing_key(issuer_key_file, "issuer key file")
    bundle = trust_bundle(
        organisation,
        keys,
        bundle_version=int(env.get("PV_TRUST_BUNDLE_VERSION", "1") or 1),
        pinned_at=env.get("PV_TRUST_BUNDLE_PINNED_AT", "").strip()
        or "2026-01-01T00:00:00Z",
    )
    public = encode_public_key(signing_key)
    if (issuer_key_id, public) not in keys:
        raise ConfigError(
            f"issuer key {issuer_key_id!r} with this public key is not in PV_ISSUER_KEYS; "
            "the gate would refuse it as RECEIVER_TRUST_ROOT_UNKNOWN"
        )
    return Issuer(
        signing_key=signing_key,
        key_id=issuer_key_id,
        organisation_id=organisation,
        bundle=bundle,
        receiver_id=need("PV_RECEIVER_ID"),
        destination=need("PV_RECEIVER_DESTINATIONS").split(";")[0].strip(),
    )


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gate", default="http://localhost:8080")
    parser.add_argument("--upstream", default="http://localhost:9001", help="demo only")
    parser.add_argument("--issuer-key", default=str(here / "keys" / "issuer.key"))
    parser.add_argument("--issuer-key-id", default="ea-signer")
    parser.add_argument("--env-file", default=str(here / ".env"))
    args = parser.parse_args(argv)

    env = {**read_env_file(Path(args.env_file)), **os.environ}
    try:
        issuer = issuer_from(
            env, issuer_key_file=Path(args.issuer_key), issuer_key_id=args.issuer_key_id
        )
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    try:
        steps = run(issuer, urllib_sender(args.gate), urllib_seen(args.upstream))
    except (urllib.error.URLError, OSError) as exc:
        print(f"cannot reach gate or upstream: {exc}", file=sys.stderr)
        return 2
    print(report(steps))
    return exit_code(steps)


if __name__ == "__main__":
    sys.exit(main())
