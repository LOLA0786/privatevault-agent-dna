"""Read-only HTTP client for PrivateVault's audit surface.

Uses only endpoints an audit-scoped key may call (``/v1/audit/export``,
``/v1/verify``, ``/v1/ops/summary``, ``/v1/revocations``). An audit key
cannot decide, authorize, approve or revoke, so the connector built on
this client cannot either: read-only is enforced by the API key scope,
not only by the tool annotations.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

DEFAULT_TIMEOUT_S = 10.0


class AuditApiError(RuntimeError):
    """An audit endpoint failed. The message is safe to show a user:
    it carries the endpoint, status and the API's own detail, never the
    API key."""


class AuditApiClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        http: httpx.Client | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if not api_key:
            raise ValueError("an audit-scoped PrivateVault API key is required")
        self._headers = {"X-API-Key": api_key}
        self._http = http or httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout_s
        )

    def _get(self, path: str) -> httpx.Response:
        try:
            response = self._http.get(path, headers=self._headers)
        except httpx.HTTPError as exc:
            raise AuditApiError(
                f"PrivateVault API unreachable at {path}: {type(exc).__name__}"
            ) from None
        if response.status_code == 401:
            raise AuditApiError(
                "PrivateVault rejected the connector's API key "
                "(missing, wrong, or not audit/full scope)"
            )
        if response.status_code >= 400:
            detail: Any = ""
            try:
                detail = response.json().get("detail", "")
            except ValueError:
                detail = ""
            suffix = f": {detail}" if detail else ""
            raise AuditApiError(f"{path} returned HTTP {response.status_code}{suffix}")
        return response

    def records(self) -> list[dict[str, Any]]:
        """Every sealed record (decisions and execution events), oldest first."""
        text = self._get("/v1/audit/export").text
        out: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                raise AuditApiError(
                    "audit export contained a malformed record"
                ) from None
            if isinstance(row, dict):
                out.append(row)
        return out

    def is_enforcement_key(self) -> bool:
        """True if this key passes an enforcement-only endpoint (full scope,
        or a deployment with authentication disabled). An audit-scoped key
        is refused there with 401."""
        try:
            response = self._http.get("/v1/runtime", headers=self._headers)
        except httpx.HTTPError:
            return True  # cannot prove it is audit-only: treat as not acceptable
        return response.status_code != 401

    def verify(self) -> dict[str, Any]:
        return dict(self._get("/v1/verify").json())

    def ops_summary(self) -> dict[str, Any]:
        return dict(self._get("/v1/ops/summary").json())

    def revocations(self) -> dict[str, Any]:
        return dict(self._get("/v1/revocations").json())
