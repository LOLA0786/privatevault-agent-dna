"""Human approval for wrapped MCP calls: ``pv approve`` (ADR 0036).

A payment tool behind ``pv wrap`` should run only when a person approves
that exact call. The gateway's decisions already turn REQUIRE_APPROVAL into
ALLOW when a verified, single-use approval for the same execution action is
presented (ADR 0020); this module is the local channel that produces one.

    pv approvers init --principal you@company.example     # once
    (Claude calls mcp__stripe__create_refund ... -> refused, with an id)
    pv approve 3f9c2a1b7e04                               # in a terminal
    (Claude retries the same call -> it runs, once)

How it works:

- ``pv approvers init`` creates an approver trust bundle in
  ``~/.privatevault/approvers``: a root key, the approver's signing key and a
  receipt key (owner-only), the bundle and the approver's authority grant.
  ``pv wrap`` pins the bundle (``PV_APPROVER_TRUST_BUNDLE``).
- When a call needs approval, the gateway writes the exact execution action
  to ``approvals/pending/<id>.json`` and tells Claude the id.
- ``pv approve <id>`` shows the tool and arguments, needs a terminal and a
  typed ``yes``, then signs an approval for that action's digest (valid five
  minutes) into ``approvals/approved/``.
- On the retry the gateway presents it; the engine verifies signature,
  authority chain, validity, action digest, subject and separation of duties,
  and claims it single-use in the ledger. Different arguments are a different
  action and are not covered.

The approver keys live on the same machine as the agent. They are in
PrivateVault's state folder, which Claude cannot read or write (the hook
blocks it, and under ``pv claude`` the OS sandbox denies it), ``pv approve``
refuses without a terminal (Claude's Bash has none), and ``pv`` is not on the
starter shell allowlist. For approvers on another machine, keep the keys
there and copy the approval file across.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_dna.quickstart import (
    AGENT_ID,
    QuickstartError,
    check_private,
    prepare_home,
)

APPROVERS_DIR = "approvers"
APPROVALS_DIR = "approvals"
BUNDLE_FILE = "bundle.json"
GRANT_FILE = "grant.json"
ORGANISATION = "local.privatevault"
ROOT_KEY_ID = "owner-root"
APPROVER_KEY_ID = "approver"
RECEIPT_KEY_ID = "approvals-runtime"
REQUEST_TTL_S = 600
APPROVAL_TTL_S = 300
ID_RE = re.compile(r"[0-9a-f]{12}")
ZERO = "sha256:" + "0" * 64
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(STAMP)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    check_private(path, directory=True)
    return path


def _write_private(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read_seed(path: Path):
    from nacl.signing import SigningKey

    check_private(path, directory=False)
    return SigningKey(bytes.fromhex(path.read_text(encoding="ascii").strip()))


def _new_seed(path: Path) -> None:
    from nacl.signing import SigningKey

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(bytes(SigningKey.generate()).hex() + "\n")


def approvers_dir(home: Path) -> Path:
    return home / APPROVERS_DIR


def bundle_path(home: Path) -> Path | None:
    """The approver bundle, if ``pv approvers init`` has run."""
    path = approvers_dir(home) / BUNDLE_FILE
    return path if path.is_file() else None


def init_approvers(home: Path, principal: str) -> Path:
    """Create the approver keys, trust bundle and authority grant."""
    from agent_dna.approval_v01 import APPROVAL_AUTHORITY_ACTION
    from agent_dna.authority_v01 import (
        CANONICALIZATION,
        GRANT_SPEC,
        TRUST_SPEC,
        encode_public_key,
        sign_grant,
    )

    if principal.split("@", 1)[0] in {"claude-code", AGENT_ID}:
        raise QuickstartError("the approver cannot be the agent")
    if not principal or principal.strip() != principal or "@" not in principal:
        raise QuickstartError("--principal must look like you@company.example")
    folder = _private_dir(approvers_dir(home))
    for name in ("root.key", "approver.key", "receipt.key"):
        if not (folder / name).exists():
            _new_seed(folder / name)
    root = _read_seed(folder / "root.key")
    approver = _read_seed(folder / "approver.key")
    receipt = _read_seed(folder / "receipt.key")
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORGANISATION,
        "bundle_version": 1,
        "pinned_at": _stamp(datetime.now(UTC)),
        "keys": [
            {
                "key_id": ROOT_KEY_ID,
                "principal": f"owner@{ORGANISATION}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(root),
                "usages": ["root_authority", "grant_issuer"],
            },
            {
                "key_id": APPROVER_KEY_ID,
                "principal": principal,
                "algorithm": "ed25519",
                "public_key": encode_public_key(approver),
                "usages": ["approval_signer", "subject"],
            },
            {
                "key_id": RECEIPT_KEY_ID,
                "principal": f"approvals-runtime@{ORGANISATION}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(receipt),
                "usages": ["receipt_signer"],
            },
        ],
    }
    now = datetime.now(UTC)
    grant = sign_grant(
        {
            "spec": GRANT_SPEC,
            "canonicalization": CANONICALIZATION,
            "grant_id": f"g-{uuid.uuid4()}",
            "organisation_id": ORGANISATION,
            "issuer_principal": f"owner@{ORGANISATION}",
            "issuer_key_id": ROOT_KEY_ID,
            "subject_principal": principal,
            "subject_key_id": APPROVER_KEY_ID,
            "parent_grant_digest": None,
            "capabilities": [
                {
                    "action": APPROVAL_AUTHORITY_ACTION,
                    "resource": "approval_request:*",
                    "constraints": [],
                    "obligations": [],
                }
            ],
            "can_delegate": False,
            "remaining_depth": 1,
            "valid_from": _stamp(now - timedelta(minutes=5)),
            "expires_at": _stamp(now + timedelta(days=365)),
        },
        root,
    )
    _write_private(folder / BUNDLE_FILE, json.dumps(bundle, indent=2) + "\n")
    _write_private(folder / GRANT_FILE, json.dumps(grant, indent=2) + "\n")
    return folder / BUNDLE_FILE


# --------------------------------------------------------------- pending


def _approvals(home: Path, kind: str) -> Path:
    _private_dir(home / APPROVALS_DIR)
    return _private_dir(home / APPROVALS_DIR / kind)


def pending_id(action_digest: str) -> str:
    return action_digest.split(":", 1)[-1][:12]


def write_pending(
    home: Path, *, agent_id: str, capability: str, arguments: dict, action: dict
) -> str:
    from agent_dna.action_v01 import execution_action_digest

    digest = execution_action_digest(action)
    ident = pending_id(digest)
    record = {
        "id": ident,
        "created_at": time.time(),
        "agent_id": agent_id,
        "capability": capability,
        "arguments": arguments,
        "execution_action": action,
        "action_digest": digest,
    }
    _write_private(_approvals(home, "pending") / f"{ident}.json", json.dumps(record))
    return ident


def read_pending(home: Path, ident: str) -> dict[str, Any]:
    if not ID_RE.fullmatch(ident):
        raise QuickstartError(f"{ident!r} is not an approval id (12 hex characters)")
    path = _approvals(home, "pending") / f"{ident}.json"
    try:
        check_private(path, directory=False)
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, QuickstartError) as exc:
        raise QuickstartError(f"no pending approval {ident}") from exc
    if time.time() - float(record.get("created_at", 0)) > REQUEST_TTL_S:
        path.unlink(missing_ok=True)
        raise QuickstartError(
            f"approval {ident} expired; ask Claude to make the call again"
        )
    return record


def list_pending(home: Path) -> list[dict[str, Any]]:
    out = []
    for path in sorted(_approvals(home, "pending").glob("*.json")):
        try:
            out.append(read_pending(home, path.stem))
        except QuickstartError:
            continue
    return out


# --------------------------------------------------------------- approve


def sign_approval(home: Path, pending: dict[str, Any]) -> dict[str, Any]:
    """The approval triple for this pending call, signed by the approver."""
    from agent_dna.approval_v01 import (
        APPROVAL_ARTIFACT_SPEC,
        APPROVAL_AUTHORITY_ACTION,
        APPROVAL_REQUEST_SPEC,
        approval_request_digest,
        sign_approval_artifact,
    )
    from agent_dna.authority_v01 import (
        CANONICALIZATION,
        COMPOSITION_PROFILE,
        RECEIPT_SPEC,
        receipt_digest,
        sign_receipt,
    )

    folder = approvers_dir(home)
    if bundle_path(home) is None:
        raise QuickstartError("no approvers yet: run pv approvers init --principal ...")
    bundle = json.loads((folder / BUNDLE_FILE).read_text(encoding="utf-8"))
    grant = json.loads((folder / GRANT_FILE).read_text(encoding="utf-8"))
    principal = next(
        k["principal"] for k in bundle["keys"] if k["key_id"] == APPROVER_KEY_ID
    )
    approver = _read_seed(folder / "approver.key")
    receipt_key = _read_seed(folder / "receipt.key")
    now = datetime.now(UTC).replace(microsecond=0)
    request = {
        "spec": APPROVAL_REQUEST_SPEC,
        "canonicalization": CANONICALIZATION,
        "approval_request_id": f"apr-{uuid.uuid4()}",
        "organisation_id": ORGANISATION,
        "request_id": pending["id"],
        "created_at": _stamp(now - timedelta(seconds=5)),
        "expires_at": _stamp(now + timedelta(seconds=REQUEST_TTL_S)),
        "nonce": uuid.uuid4().hex,
        "decision_input_digest": ZERO,
        "action": dict(pending["execution_action"]),
        "action_digest": pending["action_digest"],
        "evidence_manifest_digest": ZERO,
        "presentation_digest": ZERO,
        "approval_requirement_digest": ZERO,
    }
    request_digest = approval_request_digest(request)
    receipt = sign_receipt(
        {
            "spec": RECEIPT_SPEC,
            "canonicalization": CANONICALIZATION,
            "receipt_id": f"r-{uuid.uuid4()}",
            "organisation_id": ORGANISATION,
            "previous_receipt_hash": None,
            "request_id": request["approval_request_id"],
            "decision_timestamp": _stamp(now - timedelta(seconds=3)),
            "decision_input_digest": request_digest,
            "grant_chain": [grant],
            "requested": {
                "subject_principal": principal,
                "subject_key_id": APPROVER_KEY_ID,
                "action": APPROVAL_AUTHORITY_ACTION,
                "resource": "approval_request:" + request["approval_request_id"],
                "facts": {},
            },
            "authority_result": {
                "verdict": "ALLOW",
                "reason_code": "AUTHORITY_GRANTED",
            },
            "policy_result": {
                "verdict": "ALLOW",
                "policy_id": "PV-APPROVE",
                "policy_version": "1.0",
                "policy_digest": ZERO,
            },
            "composition_profile": COMPOSITION_PROFILE,
            "final_verdict": "ALLOW",
            "signer_key_id": RECEIPT_KEY_ID,
        },
        receipt_key,
    )
    artifact = sign_approval_artifact(
        {
            "spec": APPROVAL_ARTIFACT_SPEC,
            "canonicalization": CANONICALIZATION,
            "approval_id": f"approval-{uuid.uuid4()}",
            "approval_request_id": request["approval_request_id"],
            "approval_request_digest": request_digest,
            "organisation_id": ORGANISATION,
            "request_id": pending["id"],
            "decision_input_digest": ZERO,
            "action_digest": pending["action_digest"],
            "evidence_manifest_digest": ZERO,
            "presentation_digest": ZERO,
            "approval_requirement_digest": ZERO,
            "approver_principal": principal,
            "approver_key_id": APPROVER_KEY_ID,
            "approver_authority_digest": receipt_digest(receipt),
            "decision": "APPROVE",
            "decided_at": _stamp(now - timedelta(seconds=1)),
            "expires_at": _stamp(now + timedelta(seconds=APPROVAL_TTL_S)),
        },
        approver,
    )
    return {
        "request": request,
        "artifact": artifact,
        "approver_authority_receipt": receipt,
    }


def approve(home: Path, ident: str) -> Path:
    """Sign an approval for a pending call and file it for the retry."""
    pending = read_pending(home, ident)
    triple = sign_approval(home, pending)
    digest_hex = pending["action_digest"].split(":", 1)[-1]
    path = _approvals(home, "approved") / f"{digest_hex}.json"
    _write_private(path, json.dumps(triple))
    (_approvals(home, "pending") / f"{ident}.json").unlink(missing_ok=True)
    return path


# --------------------------------------------------------------- gateway side


class ApprovingMiddleware:
    """Wraps the gateway's ConnectorMiddleware: presents a filed approval
    for exactly this call, and files a pending request when a call needs
    one (ADR 0036)."""

    def __init__(self, inner: Any, home: Path, *, configured: bool) -> None:
        self.inner = inner
        self.home = home
        self.configured = configured

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def handle(self, request: Any) -> Any:
        from agent_dna.action_v01 import execution_action_digest
        from agent_dna.connector.middleware import execution_action_for

        agent_id = self.inner.keys.verify_scope(request.api_key, "full")
        if agent_id is None or not self.configured:
            verdict = self.inner.handle(request)
            if verdict.decision == "require_approval" and agent_id is not None:
                return dataclasses.replace(
                    verdict,
                    reason=verdict.reason
                    + " (no approval channel: set up approvers with "
                    "pv approvers init --principal you@company.example)",
                )
            return verdict
        action = execution_action_for(request, agent_id)
        digest = execution_action_digest(action)
        filed = _approvals(self.home, "approved") / f"{digest.split(':', 1)[-1]}.json"
        presented = False
        if filed.is_file():
            try:
                check_private(filed, directory=False)
                request = dataclasses.replace(
                    request, approval=json.loads(filed.read_text(encoding="utf-8"))
                )
                presented = True
            except (OSError, ValueError, QuickstartError):
                filed.unlink(missing_ok=True)
        verdict = self.inner.handle(request)
        if presented:
            filed.unlink(missing_ok=True)  # used, refused or expired: never twice
        if verdict.decision == "require_approval":
            ident = write_pending(
                self.home,
                agent_id=agent_id,
                capability=request.tool,
                arguments=dict(request.arguments),
                action=action,
            )
            return dataclasses.replace(
                verdict,
                reason=verdict.reason
                + f" -- to approve this one call, run in a terminal: pv approve {ident}"
                " ; then ask Claude to make the same call again (within 5 minutes)",
            )
        return verdict


# --------------------------------------------------------------- CLI


def add_parsers(sub: argparse._SubParsersAction) -> None:
    approvers = sub.add_parser("approvers", help="who may approve wrapped calls")
    asub = approvers.add_subparsers(dest="approvers_action", required=True)
    init = asub.add_parser("init", help="create the local approver keys")
    init.add_argument("--principal", required=True, help="you@company.example")
    init.add_argument("--home", type=Path, default=Path.home() / ".privatevault")
    init.set_defaults(func=cmd_approvers_init)

    ok = sub.add_parser("approve", help="approve one pending wrapped call")
    ok.add_argument("id", nargs="?", help="the id Claude was given; none lists them")
    ok.add_argument("--home", type=Path, default=Path.home() / ".privatevault")
    ok.set_defaults(func=cmd_approve)


def cmd_approvers_init(args: argparse.Namespace) -> int:
    try:
        home = args.home.expanduser().resolve()
        prepare_home(home)
        path = init_approvers(home, args.principal)
    except QuickstartError as exc:
        print(f"pv approvers: {exc}", file=sys.stderr)
        return 2
    print(f"approver {args.principal}: keys and trust bundle in {path.parent}")
    print("restart Claude Code so pv wrap pins the bundle")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    try:
        home = args.home.expanduser().resolve()
        if args.id is None:
            pending = list_pending(home)
            for item in pending:
                print(
                    f"{item['id']}  {item['capability']}  {json.dumps(item['arguments'])}"
                )
            if not pending:
                print("nothing waiting for approval")
            return 0
        if not sys.stdin.isatty():
            raise QuickstartError(
                "pv approve needs a person at a terminal (it refuses when run "
                "without one, as an agent's shell would)"
            )
        item = read_pending(home, args.id)
        print(f"Claude Code ({item['agent_id']}) asks to call {item['capability']}")
        print(json.dumps(item["arguments"], indent=2, sort_keys=True))
        answer = input("Approve this one call? Type yes: ").strip().lower()
        if answer != "yes":
            print("not approved")
            return 1
        approve(home, args.id)
    except QuickstartError as exc:
        print(f"pv approve: {exc}", file=sys.stderr)
        return 2
    print(f"approved {args.id} for 5 minutes; ask Claude to make the same call again")
    return 0
