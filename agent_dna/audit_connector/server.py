"""PrivateVault Audit: a read-only remote MCP server for risk and audit teams.

Lets someone ask Claude, in plain language, what AI agents did under
PrivateVault: which actions were blocked or held for approval, what one
agent did, the details of one decision, whether the record chain and
signatures verify, and which permits or agents are revoked.

Every tool is read-only (``readOnlyHint``), and the API key the server
holds is audit-scoped, so nothing reachable from here can decide,
authorize, approve, revoke or move money. Records are returned as stored:
argument digests, never raw action payloads.
"""

from __future__ import annotations

import inspect
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Any

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import AnyHttpUrl

from agent_dna.audit_connector.client import AuditApiClient, AuditApiError
from agent_dna.audit_connector.oauth import (
    LOGIN_PATH,
    SCOPE,
    AuditOAuthProvider,
    KeyCheck,
    pv_key_check,
)

SERVER_NAME = "privatevault-audit"
MAX_LIMIT = 100
MAX_EVIDENCE_ITEMS = 20
DOCS_URL = "https://github.com/LOLA0786/privatevault-agent-dna#mcp"

INSTRUCTIONS = (
    "Read-only access to a PrivateVault deployment's sealed decision records: "
    "what AI agents asked to do, what was allowed, held for human approval or "
    "blocked, and whether the audit trail verifies. Records hold argument "
    "digests, not raw payloads."
)

_SUMMARY_FIELDS = (
    "decision_id",
    "agent_id",
    "capability",
    "decision",
    "triggered_by",
    "reason",
    "severity",
    "timestamp",
    "outcome",
    "approval_ref",
    "receipt_ref",
    "record_hash",
)

_REVOCATION_FIELDS = (
    "organisation_id",
    "issued_at",
    "next_update",
    "revoked_authorizations",
    "suspended_agents",
    "organisation_suspended",
    "signer_key_id",
)


def _clamp(limit: int) -> int:
    if limit < 1:
        raise ToolError("limit must be at least 1")
    return min(limit, MAX_LIMIT)


def _api[T](call: Callable[[], T]) -> T:
    """Run one audit API call; its failure reaches the user as an
    actionable tool error (endpoint, status, API detail, never the key)."""
    try:
        return call()
    except AuditApiError as exc:
        raise ToolError(str(exc)) from None


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record.get(k) for k in _SUMMARY_FIELDS if k in record}


def _newest_first(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [_summary(r) for r in list(reversed(rows))[:limit]]


class AuditTools:
    """The connector's tools. Each method is one MCP tool; its docstring is
    the tool description Claude reads."""

    def __init__(self, client_for: Callable[[], AuditApiClient]) -> None:
        self._client_for = client_for

    @property
    def _client(self) -> AuditApiClient:
        return self._client_for()

    def _decisions(self) -> list[dict[str, Any]]:
        records = _api(self._client.records)
        return [r for r in records if r.get("kind", "decision") == "decision"]

    def list_blocked_actions(
        self,
        agent_id: str | None = None,
        include_held_for_approval: bool = False,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List agent actions PrivateVault blocked, newest first, with the
        rule and reason. Optionally filter by agent, and include actions
        held for human approval. limit is 1-100."""
        n = _clamp(limit)
        wanted = (
            {"block", "require_approval"} if include_held_for_approval else {"block"}
        )
        rows = [
            r
            for r in self._decisions()
            if r.get("decision") in wanted and agent_id in (None, r.get("agent_id"))
        ]
        return {"total": len(rows), "actions": _newest_first(rows, n)}

    def list_agent_actions(self, agent_id: str, limit: int = 20) -> dict[str, Any]:
        """List every decision PrivateVault recorded for one agent, newest
        first: capability, verdict, rule and reason. limit is 1-100."""
        n = _clamp(limit)
        rows = [r for r in self._decisions() if r.get("agent_id") == agent_id]
        if not rows:
            raise ToolError(f"no records for agent_id {agent_id!r}")
        return {
            "agent_id": agent_id,
            "total": len(rows),
            "actions": _newest_first(rows, n),
        }

    def get_decision(self, decision_id: str) -> dict[str, Any]:
        """Full sealed record of one decision: verdict, rule, reason,
        evidence, approval and receipt references, argument digest and
        hash-chain links."""
        record = next(
            (r for r in self._decisions() if r.get("decision_id") == decision_id), None
        )
        if record is None:
            raise ToolError(f"no decision with decision_id {decision_id!r}")
        out = dict(record)
        evidence = out.get("evidence")
        if isinstance(evidence, list) and len(evidence) > MAX_EVIDENCE_ITEMS:
            out["evidence"] = evidence[:MAX_EVIDENCE_ITEMS]
            out["evidence_truncated"] = len(evidence)
        return out

    def verify_audit_trail(self) -> dict[str, Any]:
        """Check that every agent's record hash chain is intact and that
        each record's signature verifies against the deployment's trusted
        keys. Reports per-agent chain status and signature counts."""
        result = _api(self._client.verify)
        chains = result.get("chains") or {}
        return {
            "chain_integrity_verified": bool(result.get("chain_integrity_verified")),
            "agents_checked": len(chains),
            "broken_chains": sorted(agent for agent, ok in chains.items() if not ok),
            "signatures": result.get("signatures"),
        }

    def activity_summary(self) -> dict[str, Any]:
        """Counts of recorded decisions by verdict and by agent, plus the
        deployment's runtime metrics."""
        decisions = self._decisions()
        by_agent: dict[str, Counter[str]] = {}
        for r in decisions:
            by_agent.setdefault(str(r.get("agent_id")), Counter())[
                str(r.get("decision"))
            ] += 1
        return {
            "decisions": len(decisions),
            "by_verdict": dict(Counter(str(r.get("decision")) for r in decisions)),
            "by_agent": {agent: dict(c) for agent, c in sorted(by_agent.items())},
            "runtime": _api(self._client.ops_summary),
        }

    def list_revocations(self) -> dict[str, Any]:
        """Current signed revocation list: revoked permits, suspended
        agents, whether the organisation is suspended, and its validity
        window."""
        doc = _api(self._client.revocations)
        out = {k: doc.get(k) for k in _REVOCATION_FIELDS}
        out["signed"] = "signature" in doc
        return out


_TITLES = {
    "list_blocked_actions": "List blocked agent actions",
    "list_agent_actions": "List one agent's actions",
    "get_decision": "Get one decision",
    "verify_audit_trail": "Verify the audit trail",
    "activity_summary": "Agent activity summary",
    "list_revocations": "List revocations",
}


def _register(server: MCPServer, tools: AuditTools) -> MCPServer:
    for name, title in _TITLES.items():
        fn = getattr(tools, name)
        server.add_tool(
            fn,
            name=name,
            title=title,
            description=inspect.cleandoc(fn.__doc__ or ""),
            annotations=ToolAnnotations(
                title=title,
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        )
    return server


def _new_server(**kwargs: Any) -> MCPServer:
    return MCPServer(
        SERVER_NAME,
        title="PrivateVault Audit",
        instructions=INSTRUCTIONS,
        website_url="https://privatevault.ai",
        **kwargs,
    )


def build_server(client: AuditApiClient) -> MCPServer:
    """Local mode: one operator-held audit key, no user sign-in (loopback only)."""
    return _register(_new_server(), AuditTools(lambda: client))


def build_oauth_server(
    pv_url: str,
    public_url: str,
    *,
    path: str = "/mcp",
    key_check: KeyCheck | None = None,
    http: httpx.Client | None = None,
    extra_redirect_uris: Sequence[str] = (),
) -> tuple[MCPServer, AuditOAuthProvider]:
    """Hosted mode: each user signs in with their organisation's audit key
    (OAuth 2.0, DCR, PKCE S256). Tools run with the signed-in user's key."""
    public_url = public_url.rstrip("/")
    resource_url = public_url + path
    provider = AuditOAuthProvider(
        public_url,
        resource_url,
        key_check or pv_key_check(pv_url, http),
        extra_redirect_uris,
    )
    clients: dict[str, AuditApiClient] = {}

    def client_for() -> AuditApiClient:
        token = get_access_token()
        api_key = provider.api_key_for(token.token) if token is not None else None
        if api_key is None:
            raise ToolError(
                "not signed in, or the session expired; reconnect the connector"
            )
        client = clients.get(api_key)
        if client is None:
            client = clients.setdefault(
                api_key, AuditApiClient(pv_url, api_key, http=http)
            )
        return client

    server = _new_server(
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(public_url),
            resource_server_url=AnyHttpUrl(resource_url),
            service_documentation_url=AnyHttpUrl(DOCS_URL),
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=[SCOPE],
            validate_token_resource=False,  # load_access_token checks the resource
        ),
    )
    server.custom_route(LOGIN_PATH, methods=["GET", "POST"])(provider.login_page)
    return _register(server, AuditTools(client_for)), provider
