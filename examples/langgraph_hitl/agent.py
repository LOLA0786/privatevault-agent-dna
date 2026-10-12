"""LangGraph human-in-the-loop payment agent with PrivateVault approval binding.

Flow:  propose -> approve (interrupt) -> execute

* propose : decide + seal a REQUIRE_APPROVAL record (no grant => needs approval).
* approve : interrupt() shows the reviewer the action digest.  The resume value
            MUST echo that digest.  If the args in the graph state no longer hash
            to the echoed digest (someone edited state while paused) nothing is
            minted.  Otherwise a throwaway grant is used to re-decide the exact
            args to ALLOW, the record is sealed, and a single-use execution
            permit is minted.
* execute : the expected action and wire bytes are rebuilt from the CURRENT
            graph state (never from the permit), the permit is verified and
            consumed, and only then is the mock tool called - with the same
            args object that was verified.

No network and no LLM: ``send_payment`` appends to ``SENT``.

PrivateVault has no in-process mint/verify API and no REQUIRE_APPROVAL -> ALLOW
transition; this file re-implements the mint sequence from api/server.py and
uses a throwaway L4 grant as the approval-to-ALLOW bridge (see the design notes).
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import operator
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from nacl.signing import SigningKey

from agent_dna.advisory import Severity
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import (
    bind_authorize_to_sealed_allow,
    mint_bindings_digest,
)
from agent_dna.decision import Decision, DecisionEngine, DecisionResult
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sign_execution_authorization,
    verify_execution_authorization,
)
from agent_dna.grants import GrantRegistry
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from agent_dna.wire_serialization_v01 import (
    WIRE_SERIALIZATION_JSON_PARAMETERS_V01 as SER,
)
from agent_dna.wire_serialization_v01 import wire_bytes_digest_from_action

ORG = "demo.example"
AGENT = "pay-agent"
CAP = "payments.send_payment"
Z = "sha256:" + "0" * 64  # placeholder digests for an in-process tool (friction F8)
PEER = b"in-process:send_payment"
PERMIT_TTL_S = 300

# ---------------------------------------------------------------- mock tool
SENT: list[dict] = []


def send_payment(to: str, amount: int, currency: str) -> str:
    SENT.append({"to": to, "amount": amount, "currency": currency})
    return f"paid {amount} {currency} to {to}"


# ------------------------------------------------------------ helper funcs
def _rfc(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize(args: dict) -> dict:
    """Integer minor units only.  Floats/bools are refused: PrivateVault's
    canonicalizer forbids floats, and 5000 / "5000" / 5000.0 are different calls."""
    amt = args.get("amount")
    if isinstance(amt, bool) or not isinstance(amt, int):
        raise ValueError(
            f"amount must be an int (minor units), got {type(amt).__name__}"
        )
    return {
        "to": str(args["to"]),
        "amount": amt,
        "currency": str(args.get("currency", "USD")),
    }


def cap_for(tool_name: str) -> str:
    """State-supplied tool name -> capability.  Unknown names map to a value that
    can never match a sealed action, so a rename while paused is a mismatch."""
    return CAP if tool_name == "send_payment" else f"unmapped.{tool_name}"


def exec_action(args: dict, cap: str = CAP) -> dict:
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": cap,
        "resource": "payments:outbound",
        "parameters": dict(args),
    }


def dispatch_ctx() -> dict:
    return {
        "adapter": "in-process",  # must equal transport (friction F3)
        "transport": "in-process",
        "operation": "call send_payment",
        "destination": "payments.local",
        "wire_content_type": "application/json",
        "serialization": SER,
    }


def ea_dispatch(thread_id: str, tool_call_id: str) -> dict:
    c = dispatch_ctx()
    return {
        "transport": c["transport"],
        "destination": c["destination"],
        "operation": c["operation"],
        "wire_content_type": c["wire_content_type"],
        "wire_content_encoding": "identity",
        "tool_id": "send_payment.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": Z,
        "credential_audience": "payments.local",
        "idempotency_key_digest": sha256_digest(
            {"thread_id": thread_id, "tool_call_id": tool_call_id}
        ),
        "retry_policy_digest": Z,
        "serialization": SER,
    }


def action_digest(args: dict) -> str:
    """Digest shown to (and echoed by) the reviewer."""
    return sha256_digest(exec_action(args))


class Verdict:
    def __init__(self, ok: bool, reason: str, failures: list[str] | None = None):
        self.ok = ok
        self.reason = reason
        self.failures = failures or []

    def __repr__(self) -> str:  # pragma: no cover
        return f"Verdict(ok={self.ok}, reason={self.reason!r})"


# ------------------------------------------------------------------ gate
class PVGate:
    """Everything PrivateVault-specific lives here."""

    def __init__(
        self, db_path: str | Path, timings: dict[str, list[float]] | None = None
    ):
        self.store = SQLiteDecisionStore(db_path)
        self.recorder = DecisionRecorder(store=self.store, multi_writer_safe=True)
        self.sk = SigningKey.generate()
        self.trust = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": ORG,
            "bundle_version": 1,
            "pinned_at": "2026-09-30T00:00:00Z",
            "keys": [
                {
                    "key_id": "ea-1",
                    "principal": f"execution-runtime@{ORG}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(self.sk),
                    "usages": ["execution_authorization_signer"],
                }
            ],
        }
        # No grant for send_payment => REQUIRE_APPROVAL, by design.
        self.engine = DecisionEngine(authorizer=GrantRegistry())
        self.timings = timings

    @contextlib.contextmanager
    def _t(self, stage: str):
        if self.timings is None:
            yield
            return
        t0 = time.perf_counter_ns()
        try:
            yield
        finally:
            self.timings.setdefault(stage, []).append(
                (time.perf_counter_ns() - t0) / 1e6
            )

    @staticmethod
    def rid(tid: str, cid: str) -> str:
        return f"{tid}:{cid}"

    def _action(self, tid: str, cid: str, args: dict) -> AgentAction:
        return AgentAction(
            agent_id=AGENT,
            capability=CAP,
            timestamp=time.time(),
            arguments=dict(args),
            request_id=self.rid(tid, cid),
        )

    # -- propose ---------------------------------------------------------
    def propose(self, tid: str, cid: str, args: dict) -> dict:
        act = self._action(tid, cid, args)
        with self._t("decide"):
            r = self.engine.decide(act)
        if r.decision is not Decision.REQUIRE_APPROVAL:
            # ALLOW would mean someone configured a standing grant: not what
            # this harness models.  Anything else is a block.  Fail closed.
            with self._t("record"):
                rec = self.recorder.record(act, r)
            return {
                "status": "blocked",
                "reason": f"propose:{r.decision.value}",
                "proposal_decision_id": rec.decision_id,
            }
        with self._t("record"):
            rec = self.recorder.record(
                act,
                r,
                execution_action=exec_action(args),
                dispatch_context=dispatch_ctx(),
            )
        return {"status": "awaiting", "proposal_decision_id": rec.decision_id}

    # -- approve -> mint ---------------------------------------------------
    def mint_for_approval(self, tid: str, cid: str, args: dict, reviewer: str) -> dict:
        approved_digest = action_digest(args)
        reg = GrantRegistry()
        grant = reg.grant(
            agent_id=AGENT,
            capability=CAP,
            granted_by=reviewer,
            expires_at=time.time() + 60,
            budget=args["amount"],
        )
        try:
            act = self._action(tid, cid, args)
            with self._t("decide"):
                r2 = DecisionEngine(authorizer=reg).decide(act)
            if r2.decision is not Decision.ALLOW:
                raise PermissionError(
                    f"approval re-decide was {r2.decision.value}: {r2.reason}"
                )
            with self._t("record"):
                rec = self.recorder.record(
                    act,
                    r2,
                    execution_action=exec_action(args),
                    dispatch_context=dispatch_ctx(),
                ).to_dict()
            receipt = "sha256:" + rec["record_hash"]
            with self._t("bind"):
                wd, wl, _ = wire_bytes_digest_from_action(
                    exec_action(args), serialization=SER
                )
                disp = ea_dispatch(tid, cid)
                reason = bind_authorize_to_sealed_allow(
                    rec,
                    agent_id=AGENT,
                    decision_receipt_digest=receipt,
                    action=exec_action(args),
                    dispatch=disp,
                    expected_wire_bytes_digest=wd,
                    expected_wire_bytes_length=wl,
                )
            if reason is not None:
                raise PermissionError(f"bind refused: {reason}")
            approval_d = sha256_digest(
                {
                    "approved_action_digest": approved_digest,
                    "reviewer": reviewer,
                    "grant_id": grant.grant_id,
                }
            )
            now = datetime.now(UTC).replace(microsecond=0)
            peer_d = "sha256:" + hashlib.sha256(PEER).hexdigest()
            rid = self.rid(tid, cid)
            exp = _rfc(now + timedelta(seconds=PERMIT_TTL_S))

            def factory():
                return sign_execution_authorization(
                    {
                        "spec": EXECUTION_AUTHORIZATION_SPEC,
                        "canonicalization": CANONICALIZATION,
                        "execution_authorization_id": f"eauth-{uuid.uuid4()}",
                        "organisation_id": ORG,
                        "request_id": rid,
                        "issued_at": _rfc(now),
                        "not_before": _rfc(now),
                        "expires_at": exp,
                        "nonce": uuid.uuid4().hex,
                        "decision_receipt_digest": receipt,
                        "authority_receipt_digest": Z,
                        "approval_artifact_digest": approval_d,
                        "action": exec_action(args),
                        "action_digest": approved_digest,
                        "expected_wire_bytes_digest": wd,
                        "expected_wire_bytes_length": wl,
                        "expected_peer_identity_digest": peer_d,
                        "dispatch": disp,
                        "state_snapshot_digest": Z,
                        "policy_bundle_digest": Z,
                        "trust_bundle_digest": sha256_digest(self.trust),
                        "obligations_digest": Z,
                        "max_uses": 1,
                        "signer_key_id": "ea-1",
                    },
                    self.sk,
                )

            with self._t("mint"):
                bd = mint_bindings_digest(
                    organisation_id=ORG,
                    agent_id=AGENT,
                    principal_id="local",
                    action=exec_action(args),
                    dispatch=disp,
                    expected_wire_bytes_digest=wd,
                    expected_wire_bytes_length=wl,
                    expected_peer_identity_digest=peer_d,
                    decision_receipt_digest=receipt,
                    authority_receipt_digest=Z,
                    approval_artifact_digest=approval_d,
                    state_snapshot_digest=Z,
                    policy_bundle_digest=Z,
                    obligations_digest=Z,
                )
                status, permit, _ = self.store.claim_or_replay_mint(
                    decision_id=rec["decision_id"],
                    organisation_id=ORG,
                    agent_id=AGENT,
                    principal_id="local",
                    bindings_digest=bd,
                    now=now,
                    expires_at=exp,
                    minted_at=_rfc(now),
                    authorization_factory=factory,
                    trust_bundle=self.trust,
                )
            if permit is None:
                raise PermissionError(f"mint refused: {status}")
            return {
                "permit": permit,
                "receipt": receipt,
                "decision_id": rec["decision_id"],
                "approval_digest": approval_d,
                "approved_action_digest": approved_digest,
                "status": "approved",
            }
        finally:
            reg.revoke(grant.grant_id, revoked_by="harness")

    # -- execute ---------------------------------------------------------
    def verify_and_consume(
        self, tid: str, cid: str, call: dict, args: dict, *, at_time: str | None = None
    ) -> Verdict:
        """Verify ``call['permit']`` against ``args`` (rebuilt from CURRENT state).
        Any exception (e.g. float in args -> AuthorityFormatError) fails closed."""
        try:
            with self._t("verify"):
                action = exec_action(args, cap_for(call.get("name", "send_payment")))
                _, _, wire = wire_bytes_digest_from_action(action, serialization=SER)
                rep = verify_execution_authorization(
                    call["permit"],
                    self.trust,
                    expected_request_id=self.rid(tid, cid),
                    expected_action=action,
                    expected_dispatch=ea_dispatch(tid, cid),
                    expected_decision_receipt_digest=call["receipt"],
                    expected_authority_receipt_digest=Z,
                    expected_approval_artifact_digest=call["approval_digest"],
                    expected_state_snapshot_digest=Z,
                    expected_policy_bundle_digest=Z,
                    expected_obligations_digest=Z,
                    expected_wire_bytes=wire,
                    expected_peer_identity_bytes=PEER,
                    at_time=at_time or _rfc(datetime.now(UTC)),
                    already_consumed=False,
                    consume_ledger=self.store,
                )
            return Verdict(bool(rep.ok), rep.reason_code, list(rep.failures))
        except Exception as e:  # fail closed
            return Verdict(False, f"EXCEPTION:{type(e).__name__}", [str(e)[:200]])

    def burn(self, permit: dict | None) -> None:
        """A failed verify does not consume the permit (friction F6); burn it so
        reverting the edit cannot re-enable the approval."""
        if permit:
            self.store.try_consume_execution_authorization(
                permit["execution_authorization_id"],
                organisation_id=ORG,
                consumed_at=_rfc(datetime.now(UTC)),
            )

    def record_block(self, tid: str, cid: str, args: dict, reason: str) -> str | None:
        """Harness-authored BLOCK record (DRP 0.1, can never mint)."""
        blk = DecisionResult(
            decision=Decision.BLOCK,
            triggered_by="permit_binding",
            reason=reason[:300],
            capability=CAP,
            agent_id=AGENT,
            drift_score=0.0,
            severity=Severity.CRITICAL,
        )
        try:
            act = self._action(tid, cid, args)
            return self.recorder.record(act, blk).decision_id
        except Exception:
            # args may be unrecordable (float etc.): record a digest stand-in instead
            safe = {
                "_unrecordable_args_sha256": hashlib.sha256(
                    repr(args).encode()
                ).hexdigest()
            }
            return self.recorder.record(self._action(tid, cid, safe), blk).decision_id

    def report_ok(self, decision_id: str) -> None:
        with self._t("outcome"):
            self.recorder.report_outcome(decision_id, "ok", "sent", dispatched=True)


# ----------------------------------------------------------------- graph
def merge_calls(left: dict | None, right: dict | None) -> dict:
    """Per-call dict merge so partial updates (update_state) work."""
    out = {k: dict(v) for k, v in (left or {}).items()}
    for k, v in (right or {}).items():
        out[k] = {**out.get(k, {}), **v}
    return out


class State(TypedDict, total=False):
    incoming: list  # [{"id","name","args"}] from the (mock) model
    calls: Annotated[dict, merge_calls]
    results: Annotated[list, operator.add]


def _tid(config) -> str:
    return config["configurable"]["thread_id"]


def build_graph(  # noqa: C901
    gate: PVGate,
    *,
    tool=None,
    interrupt_before: list[str] | None = None,
    checkpointer=None,
):
    tool = tool or send_payment

    def propose(state: State, config):
        tid = _tid(config)
        new: dict[str, dict] = {}
        for tc in state.get("incoming", []):
            cid = tc["id"]
            if cid in state.get("calls", {}):
                continue  # idempotent on re-entry
            if tc["name"] != "send_payment":
                new[cid] = {
                    "tool_call_id": cid,
                    "name": tc["name"],
                    "args": tc["args"],
                    "status": "blocked",
                    "reason": "unknown tool",
                }
                continue
            try:
                args = normalize(tc["args"])
            except (ValueError, KeyError) as e:
                new[cid] = {
                    "tool_call_id": cid,
                    "name": tc["name"],
                    "args": tc["args"],
                    "status": "blocked",
                    "reason": f"NORMALIZE:{e}",
                }
                continue
            new[cid] = {
                "tool_call_id": cid,
                "name": tc["name"],
                "args": args,
                **gate.propose(tid, cid, args),
            }
        return {"calls": new}

    def _next_awaiting(state: State) -> str | None:
        for cid, c in state.get("calls", {}).items():
            if c.get("status") == "awaiting":
                return cid
        return None

    def approve(state: State, config):
        tid = _tid(config)
        cid = _next_awaiting(state)
        if cid is None:
            return {}
        call = state["calls"][cid]
        # Everything before interrupt() re-runs on resume: keep it pure.  On
        # re-run `state` is the CURRENT checkpoint, so an update_state edit made
        # while paused is visible here.
        cur_args = call["args"]
        cur_digest = action_digest(cur_args)
        resp = interrupt(
            {
                "tool_call_id": cid,
                "tool": call["name"],
                "args": cur_args,
                "action_digest": cur_digest,
            }
        )
        if resp.get("decision") == "reject":
            return {
                "calls": {cid: {"status": "rejected"}},
                "results": [f"{cid}: rejected by reviewer"],
            }
        if resp.get("decision") == "edit":
            # reviewer edit = new proposal => new decision, new digest, new interrupt
            try:
                new_args = normalize(resp["args"])
            except (ValueError, KeyError) as e:
                return {
                    "calls": {cid: {"status": "blocked", "reason": f"NORMALIZE:{e}"}}
                }
            return {
                "calls": {cid: {"args": new_args, **gate.propose(tid, cid, new_args)}}
            }
        if resp.get("action_digest") != cur_digest:
            # args changed under the reviewer: they approved something else
            gate.record_block(tid, cid, cur_args, "APPROVAL_DIGEST_MISMATCH")
            return {
                "calls": {
                    cid: {"status": "blocked", "reason": "APPROVAL_DIGEST_MISMATCH"}
                },
                "results": [f"{cid}: BLOCKED APPROVAL_DIGEST_MISMATCH"],
            }
        try:
            minted = gate.mint_for_approval(
                tid, cid, cur_args, resp.get("reviewer", "reviewer")
            )
        except Exception as e:
            gate.record_block(tid, cid, cur_args, f"MINT_REFUSED:{e}")
            return {
                "calls": {cid: {"status": "blocked", "reason": f"MINT_REFUSED:{e}"}},
                "results": [f"{cid}: BLOCKED mint refused"],
            }
        return {"calls": {cid: minted}}

    def route_after_approve(state: State):
        return "approve" if _next_awaiting(state) else "execute"

    def execute(state: State, config):
        tid = _tid(config)
        upd: dict[str, dict] = {}
        results: list[str] = []
        for cid, call in state.get("calls", {}).items():
            if call.get("status") != "approved":
                continue
            args = copy.deepcopy(call["args"])  # verify and send the SAME object
            v = gate.verify_and_consume(tid, cid, call, args)
            if not v.ok:
                gate.record_block(
                    tid, cid, args, f"{v.reason}: {'; '.join(v.failures)[:200]}"
                )
                gate.burn(call.get("permit"))
                upd[cid] = {
                    "status": "blocked",
                    "reason": v.reason,
                    "failures": v.failures,
                }
                results.append(f"{cid}: BLOCKED {v.reason}")
                continue
            out = tool(**args)
            gate.report_ok(call["decision_id"])
            upd[cid] = {"status": "done"}
            results.append(f"{cid}: {out}")
        return {"calls": upd, "results": results}

    g = StateGraph(State)
    g.add_node("propose", propose)
    g.add_node("approve", approve)
    g.add_node("execute", execute)
    g.add_edge(START, "propose")
    g.add_edge("propose", "approve")
    g.add_conditional_edges("approve", route_after_approve, ["approve", "execute"])
    g.add_edge("execute", END)
    return g.compile(
        checkpointer=checkpointer or InMemorySaver(),
        interrupt_before=interrupt_before or [],
    )


def build_plain_graph(  # noqa: C901
    *, tool=None, interrupt_before: list[str] | None = None, checkpointer=None
):
    """Same shape and same interrupt(), but NO PrivateVault: approval is a plain
    boolean and execute sends whatever is in state.  Control arm / baseline."""
    tool = tool or send_payment

    def propose(state: State, config):
        new = {}
        for tc in state.get("incoming", []):
            if tc["id"] not in state.get("calls", {}):
                new[tc["id"]] = {
                    "tool_call_id": tc["id"],
                    "name": tc["name"],
                    "args": normalize(tc["args"]),
                    "status": "awaiting",
                }
        return {"calls": new}

    def _next(state):
        return next(
            (
                c
                for c, v in state.get("calls", {}).items()
                if v.get("status") == "awaiting"
            ),
            None,
        )

    def approve(state: State, config):
        cid = _next(state)
        if cid is None:
            return {}
        call = state["calls"][cid]
        resp = interrupt(
            {
                "tool_call_id": cid,
                "tool": call["name"],
                "args": call["args"],
                "action_digest": action_digest(call["args"]),
            }
        )
        if resp.get("decision") == "reject":
            return {"calls": {cid: {"status": "rejected"}}}
        return {"calls": {cid: {"status": "approved"}}}

    def execute(state: State, config):
        upd, results = {}, []
        for cid, call in state.get("calls", {}).items():
            if call.get("status") == "approved":
                results.append(f"{cid}: {tool(**copy.deepcopy(call['args']))}")
                upd[cid] = {"status": "done"}
        return {"calls": upd, "results": results}

    g = StateGraph(State)
    g.add_node("propose", propose)
    g.add_node("approve", approve)
    g.add_node("execute", execute)
    g.add_edge(START, "propose")
    g.add_edge("propose", "approve")
    g.add_conditional_edges(
        "approve",
        lambda s: "approve" if _next(s) else "execute",
        ["approve", "execute"],
    )
    g.add_edge("execute", END)
    return g.compile(
        checkpointer=checkpointer or InMemorySaver(),
        interrupt_before=interrupt_before or [],
    )


# -------------------------------------------------------------- driver helpers
def start(graph, thread_id: str, calls: list[dict]):
    cfg = {"configurable": {"thread_id": thread_id}}
    out = graph.invoke({"incoming": calls, "calls": {}, "results": []}, cfg)
    return cfg, out


def approve_shown(graph, cfg, reviewer: str = "reviewer:alice"):
    """Reviewer approves exactly what the pending interrupt displayed."""
    pending = graph.get_state(cfg).interrupts[0].value
    return graph.invoke(
        Command(
            resume={
                "decision": "approve",
                "action_digest": pending["action_digest"],
                "reviewer": reviewer,
            }
        ),
        cfg,
    )


def resume(graph, cfg, payload: dict):
    return graph.invoke(Command(resume=payload), cfg)
