"""OAuth 2.0 for the PrivateVault Audit connector.

The connector is its own authorization server (same origin as the MCP
endpoint). Claude registers itself by Dynamic Client Registration
(RFC 7591), sends the user to ``/authorize`` with PKCE S256, and the user
signs in on our ``/login`` page with their organisation's audit-scoped
PrivateVault API key. The key is checked live against the PrivateVault
API and must be audit scope: a full-scope (enforcement) key is refused,
so the credential behind every token can only read.

Tokens are opaque random strings. Each one is bound to the client, the
resource (this MCP endpoint) and the user's key; the key stays on the
server and is never returned to Claude. Refresh tokens rotate on use and
the previous pair is revoked.

State is held in memory: a restart signs every user out, and one process
serves one deployment. A durable store is a separate step.
"""

from __future__ import annotations

import html
import secrets
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from agent_dna.audit_connector.client import AuditApiClient, AuditApiError

SCOPE = "audit:read"
LOGIN_PATH = "/login"
LOGIN_TTL_S = 600
CODE_TTL_S = 300
ACCESS_TTL_S = 3600
REFRESH_TTL_S = 30 * 24 * 3600
MAX_KEY_LENGTH = 512
MAX_CLIENTS = 10_000
MAX_PENDING = 10_000
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

KeyCheck = Callable[[str], str | None]
"""Return None if the key is an audit-scoped PrivateVault key, else a
user-facing reason it was refused."""


def _token() -> str:
    return secrets.token_urlsafe(32)


def _subject() -> str:
    """Opaque per-sign-in subject. Not derived from the key, so nothing
    about the key leaves the server, even in token claims."""
    return "pv-audit-" + secrets.token_hex(8)


def redirect_allowed(uri: str, extra: Sequence[str] = ()) -> bool:
    """Claude's hosted callback, a loopback redirect on any port (Claude
    Code, RFC 8252), or an operator-listed URI. Anything else is refused at
    registration, so a sign-in can only send a code back to Claude."""
    if uri == CLAUDE_CALLBACK or uri in extra:
        return True
    parsed = urlparse(uri)
    return parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK_HOSTS


def pv_key_check(base_url: str, http: httpx.Client | None = None) -> KeyCheck:
    """Live check against the PrivateVault API: the key must read the audit
    surface and must NOT pass an enforcement endpoint."""

    def check(api_key: str) -> str | None:
        client = AuditApiClient(base_url, api_key, http=http)
        try:
            client.ops_summary()
        except AuditApiError:
            return (
                "That key was not accepted. Use your organisation's audit-scoped key."
            )
        if client.is_enforcement_key():
            return (
                "That is a full-scope (enforcement) key. The connector only accepts "
                "audit-scoped keys, which cannot approve or execute anything."
            )
        return None

    return check


@dataclass
class _Login:
    client_id: str
    client_name: str
    params: AuthorizationParams
    expires_at: float


@dataclass
class _Grant:
    """What a token authorizes: one user's audit key, for one client."""

    api_key: str
    subject: str
    client_id: str
    resource: str | None
    access: set[str] = field(default_factory=set)
    refresh: set[str] = field(default_factory=set)


class AuditOAuthProvider:
    """OAuthAuthorizationServerProvider for the audit connector."""

    def __init__(
        self,
        issuer_url: str,
        resource_url: str,
        key_check: KeyCheck,
        extra_redirect_uris: Sequence[str] = (),
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.resource_url = resource_url
        self._check = key_check
        self._extra_redirects = tuple(extra_redirect_uris)
        self._lock = threading.Lock()
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._logins: dict[str, _Login] = {}
        self._codes: dict[str, tuple[AuthorizationCode, _Grant]] = {}
        self._access: dict[str, tuple[AccessToken, _Grant]] = {}
        self._refresh: dict[str, tuple[RefreshToken, _Grant]] = {}

    # ---- clients (RFC 7591) -------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            raise ValueError("client_id missing")
        for uri in client_info.redirect_uris or []:
            if not redirect_allowed(str(uri), self._extra_redirects):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=f"redirect URI not allowed for this connector: {uri}",
                )
        if len(self._clients) >= MAX_CLIENTS:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="registration limit reached; try again later",
            )
        self._clients[client_info.client_id] = client_info

    # ---- authorization ------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource and params.resource.rstrip("/") != self.resource_url.rstrip(
            "/"
        ):
            raise AuthorizeError(
                error="invalid_request",
                error_description="resource does not match this MCP server",
            )
        txn = _token()
        with self._lock:
            self._prune()
            if len(self._logins) >= MAX_PENDING:
                raise AuthorizeError(
                    error="temporarily_unavailable",
                    error_description="too many sign-ins in progress; try again shortly",
                )
            self._logins[txn] = _Login(
                client_id=str(client.client_id),
                client_name=client.client_name or "an MCP client",
                params=params,
                expires_at=time.time() + LOGIN_TTL_S,
            )
        return f"{self.issuer_url}{LOGIN_PATH}?txn={txn}"

    def _prune(self) -> None:
        now = time.time()
        for txn in [t for t, login in self._logins.items() if login.expires_at < now]:
            del self._logins[txn]
        for code in [c for c, (ac, _) in self._codes.items() if ac.expires_at < now]:
            del self._codes[code]

    def _pending(self, txn: str) -> _Login | None:
        login = self._logins.get(txn)
        if login is None or login.expires_at < time.time():
            return None
        return login

    async def login_page(self, request: Request) -> Response:
        txn = request.query_params.get("txn", "")
        login = self._pending(txn)
        if login is None:
            return _page("Sign-in link expired", "<p>Start again from Claude.</p>", 400)
        if request.method == "GET":
            return _login_form(txn, login, error=None)

        form = await request.form()
        api_key = str(form.get("api_key", "")).strip()
        if not api_key or len(api_key) > MAX_KEY_LENGTH:
            return _login_form(txn, login, error="Enter your audit-scoped key.")
        refusal = self._check(api_key)
        if refusal is not None:
            return _login_form(txn, login, error=refusal)

        with self._lock:
            if self._logins.pop(txn, None) is None:  # single use
                return _page(
                    "Sign-in link already used", "<p>Start again from Claude.</p>", 400
                )
            code = _token()
            grant = _Grant(
                api_key=api_key,
                subject=_subject(),
                client_id=login.client_id,
                resource=login.params.resource,
            )
            self._codes[code] = (
                AuthorizationCode(
                    code=code,
                    scopes=login.params.scopes or [SCOPE],
                    expires_at=time.time() + CODE_TTL_S,
                    client_id=login.client_id,
                    code_challenge=login.params.code_challenge,
                    redirect_uri=login.params.redirect_uri,
                    redirect_uri_provided_explicitly=login.params.redirect_uri_provided_explicitly,
                    resource=login.params.resource,
                    subject=grant.subject,
                ),
                grant,
            )
        target = construct_redirect_uri(
            str(login.params.redirect_uri), code=code, state=login.params.state
        )
        return RedirectResponse(target, status_code=302, headers=_SECURITY_HEADERS)

    # ---- tokens -------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        entry = self._codes.get(authorization_code)
        if entry is None or entry[0].client_id != client.client_id:
            return None
        if entry[0].expires_at < time.time():
            self._codes.pop(authorization_code, None)
            return None
        return entry[0]

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        with self._lock:
            entry = self._codes.pop(authorization_code.code, None)
        if entry is None:
            raise TokenError(
                error="invalid_grant", error_description="code already used"
            )
        return self._issue(entry[1], authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        entry = self._refresh.get(refresh_token)
        if entry is None or entry[0].client_id != client.client_id:
            return None
        return entry[0]

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        with self._lock:
            entry = self._refresh.get(refresh_token.token)
            if entry is None:
                raise TokenError(
                    error="invalid_grant", error_description="refresh token revoked"
                )
            grant = entry[1]
            self._revoke_grant_tokens(grant)  # rotate: the old pair stops working
        return self._issue(grant, scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        entry = self._access.get(token)
        if entry is None:
            return None
        access, _ = entry
        if access.expires_at is not None and access.expires_at < time.time():
            self._access.pop(token, None)
            return None
        if access.resource and access.resource.rstrip("/") != self.resource_url.rstrip(
            "/"
        ):
            return None
        return access

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        with self._lock:
            entry = self._access.get(token.token) or self._refresh.get(token.token)
            if entry is not None:
                self._revoke_grant_tokens(entry[1])

    def api_key_for(self, access_token: str) -> str | None:
        """The audit key behind a live access token (server side only)."""
        entry = self._access.get(access_token)
        return entry[1].api_key if entry is not None else None

    def _issue(self, grant: _Grant, scopes: list[str]) -> OAuthToken:
        access, refresh = _token(), _token()
        now = int(time.time())
        with self._lock:
            self._access[access] = (
                AccessToken(
                    token=access,
                    client_id=grant.client_id,
                    scopes=scopes,
                    expires_at=now + ACCESS_TTL_S,
                    resource=grant.resource,
                    subject=grant.subject,
                ),
                grant,
            )
            self._refresh[refresh] = (
                RefreshToken(
                    token=refresh,
                    client_id=grant.client_id,
                    scopes=scopes,
                    expires_at=now + REFRESH_TTL_S,
                    resource=grant.resource,
                    subject=grant.subject,
                ),
                grant,
            )
            grant.access.add(access)
            grant.refresh.add(refresh)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL_S,
            refresh_token=refresh,
            scope=" ".join(scopes),
        )

    def _revoke_grant_tokens(self, grant: _Grant) -> None:
        for t in grant.access:
            self._access.pop(t, None)
        for t in grant.refresh:
            self._refresh.pop(t, None)
        grant.access.clear()
        grant.refresh.clear()


# ---- login page -------------------------------------------------------------

_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
    "form-action 'self'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>"
        "body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1f2328}"
        "input{width:100%;padding:.6rem;font:inherit;box-sizing:border-box}"
        "button{margin-top:1rem;padding:.6rem 1.2rem;font:inherit}"
        ".err{color:#b42318}.host{font-weight:600}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    return HTMLResponse(doc, status_code=status, headers=_SECURITY_HEADERS)


def _login_form(txn: str, login: _Login, error: str | None) -> HTMLResponse:
    host = urlparse(str(login.params.redirect_uri)).hostname or "unknown"
    err = f"<p class='err'>{html.escape(error)}</p>" if error else ""
    body = (
        f"<p><b>{html.escape(login.client_name)}</b> wants read-only access to your "
        "PrivateVault audit records. It cannot approve, execute or change anything.</p>"
        f"<p>After you sign in you will be sent back to <span class='host'>{html.escape(host)}</span>. "
        "Continue only if you started this from that site.</p>"
        f"{err}<form method='post' action='{LOGIN_PATH}?txn={html.escape(txn)}'>"
        "<label for='k'>Audit-scoped PrivateVault API key</label>"
        "<input id='k' name='api_key' type='password' autocomplete='off' required>"
        "<button type='submit'>Allow read-only access</button></form>"
    )
    return _page("Sign in to PrivateVault Audit", body, 401 if error else 200)
