"""
DelegationGate -- delegation enforced on the live decision path.

``delegation.py`` is a library a receiving service calls. This gate puts the
same rules inside ``/v1/decide``, so an agent acting on handed-down
authority is checked on every call by the runtime, not by whichever caller
remembered to.

What the operator pins (``PV_DELEGATION_FILE``):

    {
      "audience": "pv-prod-eu",
      "roots":  {"operator": "<ed25519 public key>"},
      "agents": {"planner": "<key>", "payer": "<key>"},
      "revoked": ["<link hash>"],
      "revoked_agents": ["old-agent"],
      "required_for": ["payments."],
      "required_agents": ["payer"]
    }

What the caller supplies, in ``evidence["delegation"]``:

    {"chain": [...links...], "presentation": {...}}

The gate only ever RESTRICTS. A valid chain grants nothing the agent's own
grant does not: the grant check still runs, and the action must be inside
both. Without the chain, an agent listed in ``required_agents`` (or acting
on a capability in ``required_for``) is refused, so a sub-agent cannot fall
back on a standing grant to do what its delegator never handed it.

Holder binding. A chain is a document; anyone who copies it holds the same
bytes. So the caller also sends a PRESENTATION signed with the final
delegate's own key, over this chain, this exact action (agent, capability
and arguments, hashed by the service), this deployment's ``audience`` and a
lifetime of at most ``MAX_PRESENTATION_TTL`` seconds. "This exact action"
includes where it runs: the sealed destination, operation, resource and the
principal acted as (``sealed_dispatch``). Each presentation is
spent once in the shared single-use ledger. A copied chain without the key
is refused; a captured presentation is good for one action, the one it was
signed for, on one deployment, and has already been used.

This differs from ``possession.DelegationChallenges`` on purpose. That one
is a receiver-issued challenge held in one process's memory, right for a
service that talks to the agent directly. ``/v1/decide`` is one call that
may land on any replica, so the proof here is self-contained and its
single use is recorded in the ledger every replica shares.

A refusal is a BLOCK. A hold would be shown by an interactive client (the
Claude Code hook, for one) as a question the user can answer "allow", and a
forged or missing chain is not a question.

Limits:
    * A presentation's freshness rests on clocks (TTL plus 30 s skew); its
      single use rests on the ledger. With the in-memory ledger that is per
      process.
    * ``max_amount`` is per action; cumulative spend is the grant ledger's.
    * The signing key must live in a broker the model cannot read. A model
      that can sign presentations can present.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .delegation import (
    CLOCK_SKEW_SECONDS,
    TrustAnchors,
    _is_hex,
    _number,
    covers,
    within_scope,
)
from .nonce_ledger import LedgerUnavailable, MemoryNonceLedger, NonceLedger

PRESENTATION_SPEC = "pv-delegation-presentation/1"
MAX_PRESENTATION_TTL = 120.0
_TAG = b"pv-delegation-presentation/1:"
_PRESENTATION_FIELDS = frozenset(
    {
        "spec",
        "audience",
        "chain_hash",
        "action_id",
        "nonce",
        "issued_at",
        "expires_at",
        "signature",
    }
)
_CONFIG_FIELDS = frozenset(
    {
        "audience",
        "roots",
        "agents",
        "revoked",
        "revoked_agents",
        "required_for",
        "required_agents",
    }
)


class DelegationConfigError(ValueError):
    """The pinned delegation configuration is unusable. Startup must refuse."""


BOUND_FIELDS = (
    "destination",
    "operation",
    "transport",
    "wire_content_type",
    "resource",
    "subject_principal",
    "action",
)


def sealed_dispatch(
    execution_action: Mapping[str, Any], dispatch_context: Mapping[str, Any]
) -> dict[str, Any]:
    """Where and how an action will run, as the runtime seals it.

    The destination, METHOD+path, transport and content type the bytes go
    to; the resource they act on; the principal they act as. ``/v1/decide``
    builds ``evidence["bound"]`` with this, and a presentation is signed
    over the same values, so the two cannot drift apart.
    """
    sealed = {
        "destination": dispatch_context["destination"],
        "operation": dispatch_context["operation"],
        "transport": dispatch_context["transport"],
        "wire_content_type": dispatch_context["wire_content_type"],
        "resource": execution_action["resource"],
        "subject_principal": execution_action["subject_principal"],
        "action": execution_action["action"],
    }
    # Which adapter sends the bytes and how they are serialized decide what
    # reaches the wire as much as the destination does.
    for extra in ("adapter", "serialization"):
        if extra in dispatch_context:
            sealed[extra] = dispatch_context[extra]
    return sealed


def delegated_action_id(
    agent_id: str,
    capability: str,
    arguments: Mapping[str, Any] | None,
    bound: Mapping[str, Any] | None = None,
) -> str:
    """What a presentation is signed for: one exact action, where it runs.

    ``bound`` is ``sealed_dispatch(...)`` of the request: destination,
    operation, resource and the principal acted as. It is part of the hash,
    so a presentation signed for a refund to one account on one host is not
    valid for the same arguments against another resource, as another
    principal, or sent somewhere else. Before 2026-11-11 only the agent,
    capability and arguments were covered, and each of those three could be
    changed under a valid presentation.

    A request with no sealed dispatch hashes ``bound`` as null: such a
    presentation is not valid for any request that has one.
    """
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "arguments": arguments or {},
            "bound": dict(bound) if bound is not None else None,
            "capability": capability,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _presentation_bytes(presentation: Mapping[str, Any]) -> bytes:
    body = {k: v for k, v in presentation.items() if k != "signature"}
    return (
        _TAG
        + json.dumps(
            body, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def sign_presentation(
    signing_key_hex: str,
    *,
    audience: str,
    chain_hash: str,
    action_id: str,
    ttl: float = 60.0,
    now: float | None = None,
) -> dict[str, Any]:
    """Sign one presentation with the final delegate's key.

    Runs in the agent's credential broker, after the broker has checked
    that ``action_id`` is the action it means to take. Never in the model.
    """
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    issued_at = time.time() if now is None else float(now)
    presentation: dict[str, Any] = {
        "spec": PRESENTATION_SPEC,
        "audience": audience,
        "chain_hash": chain_hash,
        "action_id": action_id,
        "nonce": secrets.token_hex(32),
        "issued_at": issued_at,
        "expires_at": issued_at + float(ttl),
    }
    key = SigningKey(signing_key_hex.encode(), encoder=HexEncoder)
    presentation["signature"] = key.sign(
        _presentation_bytes(presentation)
    ).signature.hex()
    return presentation


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object with a repeated key has two readings; refuse it.

    json.loads keeps the last value silently, so a second "revoked_agents"
    lower in the file would replace the first.
    """
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _strings(raw: Any, name: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(v, str) and v for v in raw):
        raise DelegationConfigError(f"{name} must be a list of non-empty strings")
    return tuple(raw)


@dataclass(frozen=True)
class DelegationPolicy:
    audience: str
    anchors: TrustAnchors
    required_for: tuple[str, ...] = ()
    required_agents: frozenset[str] = frozenset()

    def requires(self, agent_id: str, capability: str) -> bool:
        return agent_id in self.required_agents or any(
            covers(pattern, capability) for pattern in self.required_for
        )

    @classmethod
    def from_dict(cls, raw: Any) -> DelegationPolicy:  # noqa: C901 - checklist
        if not isinstance(raw, dict):
            raise DelegationConfigError("delegation config must be a JSON object")
        unknown = set(raw) - _CONFIG_FIELDS
        if unknown:
            raise DelegationConfigError(f"unknown field(s) {sorted(unknown)}")
        audience = raw.get("audience")
        if not isinstance(audience, str) or not audience:
            raise DelegationConfigError(
                "audience must name this deployment: it stops a presentation "
                "signed for one deployment being replayed to another"
            )
        roots, agents = raw.get("roots"), raw.get("agents")
        if not isinstance(roots, dict) or not roots:
            raise DelegationConfigError("roots must be a non-empty object")
        if not isinstance(agents, dict) or not agents:
            raise DelegationConfigError("agents must be a non-empty object")
        revoked = _strings(raw.get("revoked", []), "revoked")
        if not all(_is_hex(h, 64) for h in revoked):
            raise DelegationConfigError("revoked must hold link hashes")
        required_for = _strings(raw.get("required_for", []), "required_for")
        if any("*" in p or len(p) < 2 for p in required_for):
            raise DelegationConfigError(
                "required_for takes exact names or prefixes ending in a dot"
            )
        revoked_agents = _strings(raw.get("revoked_agents", []), "revoked_agents")
        required_agents = _strings(raw.get("required_agents", []), "required_agents")
        # A name in these lists that matches no pinned identity does
        # nothing: " planner" or "Planner" would load and revoke no one.
        known = set(roots) | set(agents)
        for field_name, names, pool in (
            ("revoked_agents", revoked_agents, known),
            ("required_agents", required_agents, set(agents)),
        ):
            for name in names:
                if name in pool:
                    continue
                near = [
                    k for k in sorted(pool) if k.casefold() == name.strip().casefold()
                ]
                hint = f" (did you mean {near[0]!r}?)" if near else ""
                raise DelegationConfigError(
                    f"{field_name}: {name!r} is not a pinned identity{hint}; "
                    "it would have no effect"
                )
        try:
            anchors = TrustAnchors(
                roots=dict(roots),
                agents=dict(agents),
                revoked=frozenset(revoked),
                revoked_agents=frozenset(revoked_agents),
            )
        except ValueError as exc:
            raise DelegationConfigError(str(exc)) from exc
        return cls(
            audience=audience,
            anchors=anchors,
            required_for=required_for,
            required_agents=frozenset(required_agents),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> DelegationPolicy:
        try:
            raw = json.loads(
                Path(path).read_text(encoding="utf-8"),
                object_pairs_hook=_no_duplicate_keys,
            )
        except (OSError, ValueError) as exc:
            raise DelegationConfigError(
                f"cannot load delegation config {str(path)!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return cls.from_dict(raw)


@dataclass(frozen=True)
class GateVerdict:
    checked: bool  # False: no chain supplied and none required
    refused: bool
    reason: str = ""
    chain_hash: str | None = None
    depth: int = 0
    seal: str = ""  # appended to an ALLOW's sealed reason; see seal_delegation


SEAL_MARK = "; delegation="


def seal_delegation(
    *,
    chain_hash: str,
    depth: int,
    expires_at: float,
    links: Any,
    parties: Any,
    keys: Any = (),
) -> str:
    """What an ALLOW made under a chain must carry into its signed record.

    ``/v1/authorize`` mints a permit from the sealed decision, possibly much
    later. Without this, a decision allowed one second before its chain
    expired still minted a permit that lived a full permit lifetime, and a
    chain whose signer was revoked after the decision still minted. The
    record now says when the delegated authority ends and who it rests on;
    minting refuses after the first and on revocation of any of the second.
    """
    return SEAL_MARK + json.dumps(
        {
            "chain": chain_hash,
            "depth": depth,
            "expires_at": expires_at,
            "keys": dict(keys),
            "links": list(links),
            "parties": list(parties),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def sealed_delegation(reason: Any) -> dict[str, Any] | None:
    """The delegation a sealed decision ran under, or None if it ran under none.

    The seal is the LAST thing the engine appends, so only a final, complete
    and well-formed seal counts. Raises ValueError when a seal is present
    but unreadable: a caller must then refuse, never treat it as absent.
    """
    if not isinstance(reason, str):
        return None
    at = reason.rfind(SEAL_MARK)
    if at < 0:
        return None
    try:
        sealed = json.loads(reason[at + len(SEAL_MARK) :])
    except ValueError as exc:
        raise ValueError("sealed delegation is not valid JSON") from exc
    if (
        not isinstance(sealed, dict)
        or set(sealed) != {"chain", "depth", "expires_at", "keys", "links", "parties"}
        or not isinstance(sealed["keys"], dict)
        or not all(_is_hex(k, 64) for k in sealed["keys"].values())
        or not _is_hex(sealed["chain"], 64)
        or not _number(sealed["expires_at"])
        or not isinstance(sealed["links"], list)
        or not all(_is_hex(h, 64) for h in sealed["links"])
        or not isinstance(sealed["parties"], list)
        or not all(isinstance(p, str) and p for p in sealed["parties"])
    ):
        raise ValueError("sealed delegation is malformed")
    return sealed


_SKIPPED = GateVerdict(checked=False, refused=False)


class DelegationGate:
    def __init__(
        self,
        policy: DelegationPolicy,
        *,
        ledger: NonceLedger | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy
        self._ledger: NonceLedger = (
            ledger if ledger is not None else MemoryNonceLedger()
        )
        self._ledger_shared = ledger is not None
        self._clock = clock
        self._source: Path | None = None
        self._source_stamp: tuple[int, int] | None = None
        self._config_problem: str | None = None

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        ledger: NonceLedger | None = None,
        clock: Callable[[], float] = time.time,
    ) -> DelegationGate:
        """A gate that follows its configuration file.

        The file is re-read whenever it changes on disk, so a revocation
        written to it takes effect on the next decision or mint with no
        restart. If the changed file cannot be loaded, the gate refuses
        everything until it can: a half-written revocation must not leave
        the old, unrevoked configuration in force.
        """
        gate = cls(DelegationPolicy.from_file(path), ledger=ledger, clock=clock)
        gate._source = Path(path)
        gate._source_stamp = gate._stamp()
        return gate

    def _stamp(self) -> tuple[int, int] | None:
        assert self._source is not None
        try:
            stat = self._source.stat()
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def _refresh(self) -> None:
        if self._source is None:
            return
        stamp = self._stamp()
        if stamp == self._source_stamp and self._config_problem is None:
            return
        try:
            self.policy = DelegationPolicy.from_file(self._source)
        except DelegationConfigError as exc:
            self._config_problem = str(exc)
        else:
            self._config_problem = None
        self._source_stamp = stamp

    def use_ledger(self, ledger: NonceLedger) -> None:
        self._ledger = ledger
        self._ledger_shared = True

    def health(self) -> str | None:
        """None when a presentation could be recorded now, else why not."""
        probe = getattr(self._ledger, "health", None)
        return probe() if callable(probe) else None

    def describe(self) -> dict[str, str]:
        policy = self.policy
        required = ", ".join(policy.required_for) or "none"
        agents = ", ".join(sorted(policy.required_agents)) or "none"
        return {
            "status": "attached",
            "detail": (
                f"pv-delegation/1 on the decision path: {len(policy.anchors.roots)} "
                f"root(s), {len(policy.anchors.agents)} agent key(s), audience "
                f"{policy.audience!r}; required for capabilities: {required}; "
                f"required for agents: {agents}; holder-signed presentation, "
                "single-use: "
                f"{'shared ledger' if self._ledger_shared else 'this process only'}"
                "; configuration "
                f"{'reloaded when the file changes' if self._source else 'fixed'}"
                "; restricts only, never grants"
            ),
        }

    @staticmethod
    def _refuse(
        reason: str, chain_hash: str | None = None, depth: int = 0
    ) -> GateVerdict:
        return GateVerdict(True, True, reason, chain_hash, depth)

    def check(  # noqa: C901 - ordered refusal checklist
        self,
        *,
        agent_id: str,
        capability: str,
        arguments: Mapping[str, Any] | None,
        amount: float | None,
        evidence: Mapping[str, Any] | None,
    ) -> GateVerdict:
        """Never raises for caller input: every problem is a refusal."""
        self._refresh()
        if self._config_problem is not None:
            return self._refuse(
                f"delegation_config_invalid: {self._config_problem}; nothing is "
                "allowed under delegation until the file loads"
            )
        supplied = (evidence or {}).get("delegation")
        if supplied is None:
            if self.policy.requires(agent_id, capability):
                return self._refuse(
                    f"delegation_required: {agent_id!r} may perform "
                    f"{capability!r} only under a delegation chain, and none "
                    "was presented"
                )
            return _SKIPPED
        if not isinstance(supplied, dict) or set(supplied) != {"chain", "presentation"}:
            return self._refuse(
                "delegation_invalid: evidence must hold exactly a chain and a "
                "presentation"
            )

        now = self._clock()
        scoped = within_scope(
            supplied["chain"],
            self.policy.anchors,
            agent_id=agent_id,
            capability=capability,
            amount=amount,
            now=now,
        )
        if not scoped.allowed:
            return self._refuse(scoped.reason, scoped.chain_hash, scoped.depth)
        chain_hash, depth = scoped.chain_hash, scoped.depth
        assert chain_hash is not None

        # Server-derived, reserved key: callers cannot set evidence["bound"].
        bound = (evidence or {}).get("bound")
        if bound is not None and not isinstance(bound, Mapping):
            return self._refuse("delegation_invalid: sealed dispatch is malformed")
        try:
            problem = self._presentation_problem(
                supplied["presentation"],
                agent_id=agent_id,
                capability=capability,
                arguments=arguments,
                chain_hash=chain_hash,
                now=now,
                bound=bound,
            )
        except LedgerUnavailable as exc:
            # A presentation that cannot be recorded as spent must not pass.
            return self._refuse(
                f"delegation_ledger_unavailable: {exc}", chain_hash, depth
            )
        if problem is not None:
            return self._refuse(
                f"delegation_holder_unproven: {problem}", chain_hash, depth
            )
        assert scoped.expires_at is not None
        return GateVerdict(
            True,
            False,
            f"delegation chain {chain_hash[:16]} verified (depth {depth}), holder "
            "proven",
            chain_hash,
            depth,
            seal=seal_delegation(
                chain_hash=chain_hash,
                depth=depth,
                expires_at=scoped.expires_at,
                links=scoped.links,
                parties=scoped.parties,
                keys=scoped.keys,
            ),
        )

    def revocation_of(self, sealed: Mapping[str, Any]) -> str | None:
        """Why a sealed delegation no longer counts under today's pins.

        Checked when a permit is minted. Beyond explicit revocation, the
        decision stops counting if any party in its chain is no longer
        pinned, or is pinned under a different key than it verified with:
        rotating a key or removing an agent withdraws what was decided
        under the old one.
        """
        self._refresh()
        if self._config_problem is not None:
            return f"the delegation configuration is unusable ({self._config_problem})"
        anchors = self.policy.anchors
        for party in sealed["parties"]:
            if party in anchors.revoked_agents:
                return f"{party!r} is revoked"
            pinned = anchors.roots.get(party) or anchors.agents.get(party)
            if pinned is None:
                return f"{party!r} is no longer a pinned identity"
            if sealed["keys"].get(party) != pinned:
                return f"{party!r}'s pinned key changed since this decision"
        for digest in sealed["links"]:
            if digest in anchors.revoked:
                return f"link {digest[:16]} is revoked"
        return None

    def _presentation_problem(  # noqa: C901 - ordered refusal checklist
        self,
        presentation: Any,
        *,
        agent_id: str,
        capability: str,
        arguments: Mapping[str, Any] | None,
        chain_hash: str,
        now: float,
        bound: Mapping[str, Any] | None = None,
    ) -> str | None:
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        if (
            not isinstance(presentation, dict)
            or set(presentation) != _PRESENTATION_FIELDS
        ):
            return "malformed presentation"
        if presentation["spec"] != PRESENTATION_SPEC:
            return f"spec is not {PRESENTATION_SPEC}"
        if presentation["audience"] != self.policy.audience:
            return "signed for a different deployment (audience mismatch)"
        if presentation["chain_hash"] != chain_hash:
            return "signed for a different chain"
        try:
            expected = delegated_action_id(agent_id, capability, arguments, bound)
        except (TypeError, ValueError, RecursionError):
            return "action arguments are not canonical JSON"
        if presentation["action_id"] != expected:
            return (
                "signed for a different action (agent, capability, arguments, "
                "resource, principal, destination and operation are all covered)"
            )
        nonce, signature = presentation["nonce"], presentation["signature"]
        if not _is_hex(nonce, 64) or not _is_hex(signature, 128):
            return "malformed nonce or signature"
        issued, expires = presentation["issued_at"], presentation["expires_at"]
        if not _number(issued) or not _number(expires):
            return "timestamps must be finite numbers"
        if not 0 < expires - issued <= MAX_PRESENTATION_TTL:
            return f"lifetime must be within (0, {MAX_PRESENTATION_TTL:g}] s"
        if issued > now + CLOCK_SKEW_SECONDS:
            return "issued in the future"
        if now >= expires:
            return "expired"
        key = self.policy.anchors.agents.get(agent_id)
        if key is None:
            return f"{agent_id!r} has no pinned key to prove"
        try:
            VerifyKey(key.encode(), encoder=HexEncoder).verify(
                _presentation_bytes(presentation), bytes.fromhex(signature)
            )
        except (BadSignatureError, ValueError, TypeError, RecursionError):
            return f"signature does not verify under {agent_id!r}'s pinned key"
        # Last, and only for a presentation that verified: spend it. Garbage
        # cannot burn a real holder's nonce, and a second use is refused on
        # every replica that shares the ledger.
        entry = (f"delegation:{agent_id}", nonce, float(expires))
        if not self._ledger.consume([entry], now):
            return "presentation already used"
        return None
