"""
OPA policy adapter — enforcement-path connector to Open Policy Agent.

Design rules (2026-07 hardening):

  1. FAIL-CLOSED EVERYWHERE. Unreachable OPA, empty/malformed result,
     or a degraded bundle with no opinion raises PolicyUnavailableError;
     the engine converts that into BLOCK/engine_fault. A denial is
     never fabricated as a policy verdict no policy issued, and a
     degraded path never produces an authoritative ALLOW.
  2. ONE TOTAL DEADLINE. Retries share a single monotonic budget, so
     the worst case is bounded (default 1.0s) instead of
     attempts x timeout + backoff sleeps. Policy latency on the
     enforcement path is a p99 commitment, not an accident.
  3. RULE IDENTITY. If the Rego response carries a rule identifier, it
     is surfaced as matched_rule_id and written into
     DecisionRecord.policy_id -- an auditor traces any block to the
     exact rule. Absent it, policy_id is honestly null.
  4. CACHING IS OPT-IN AND BOUNDED. cache_ttl is the MAXIMUM POLICY
     REVOCATION LAG: a rule revoked in OPA stays live for up to that
     long. Default 0 (disabled). Denials and degraded results are
     never cached.
  5. TRANSPORT SECURITY IS CONFIGURABLE. mTLS (client cert/key),
     custom CA bundle, and bearer token, so the adapter can run inside
     a regulated VPC.

Not shipped (see docs/WHAT-WE-DO-NOT-CLAIM.md): OPA cluster/HA
failover, bundle signature verification, local Rego evaluation. The
bundle path is a degraded capability-allowlist fallback, not a Rego
engine.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class PolicyUnavailableError(RuntimeError):
    """The policy backend could not produce a verdict (unreachable,
    empty, or malformed response, or a degraded bundle with no
    opinion). Raised so the engine's fail-closed handler turns the
    fault into a BLOCK with triggered_by=engine_fault -- an
    infrastructure fault, honestly distinct in the audit trail from a
    real policy denial."""


class PolicyResult:
    """Verdict contract consumed by DecisionEngine. `fired` False means
    'policy raised no objection, continue evaluation' -- only ever
    returned when a real policy evaluation actually occurred."""

    __slots__ = ("fired", "outcome", "reason", "matched_rule_id", "degraded")

    def __init__(self, fired: bool, outcome: str, reason: str,
                 matched_rule_id: Optional[str] = None,
                 degraded: bool = False):
        self.fired = fired
        self.outcome = outcome
        self.reason = reason
        self.matched_rule_id = matched_rule_id
        self.degraded = degraded

    def __repr__(self) -> str:
        return (f"PolicyResult(fired={self.fired}, "
                f"outcome={self.outcome!r}, rule={self.matched_rule_id!r})")


class OPAPolicyAdapter:
    """Open Policy Agent connector for regulated deployments."""

    DEFAULT_ENDPOINT = "http://localhost:8181"
    DEFAULT_TIMEOUT = 2.0          # per-attempt ceiling
    DEFAULT_DEADLINE = 1.0         # TOTAL budget across all attempts
    DEFAULT_RETRY_COUNT = 3
    DEFAULT_BACKOFF = 0.05
    DEFAULT_FAIL_DECISION = "block"  # API compat; unavailable RAISES
    MAX_CACHE_ENTRIES = 1024

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        policy_path: str = "agent/governance",
        bundle_path: Optional[str] = None,
        default_decision: str = DEFAULT_FAIL_DECISION,
        cache_ttl: int = 0,
        enable_metrics: bool = True,
        *,
        deadline_seconds: Optional[float] = None,
        token: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_bundle: Optional[str] = None,
        verify_tls: bool = True,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.policy_path = policy_path
        self.bundle_path = Path(bundle_path) if bundle_path else None
        self.default_decision = default_decision
        # cache_ttl is the maximum policy-revocation lag. 0 = disabled.
        self.cache_ttl = cache_ttl
        self.enable_metrics = enable_metrics
        self.deadline_seconds = (
            deadline_seconds if deadline_seconds is not None
            else self.DEFAULT_DEADLINE
        )
        self.token = token
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_bundle = ca_bundle
        self.verify_tls = verify_tls

        self._cache: "OrderedDict[str, tuple]" = OrderedDict()
        self._request_count = 0
        self._fallback_count = 0
        self._cache_hits = 0
        self._deadline_exceeded = 0
        self._avg_latency_ms: float = 0.0
        self._ssl_context = self._build_ssl_context()

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------
    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        """mTLS / CA / verification for in-VPC deployment. None for
        plain HTTP endpoints (dev, or OPA on localhost sidecar)."""
        if not self.endpoint.startswith("https"):
            return None
        ctx = ssl.create_default_context(cafile=self.ca_bundle)
        if not self.verify_tls:
            # Explicit, never a silent default. An operator disabling
            # verification has said so in configuration.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.client_cert:
            ctx.load_cert_chain(self.client_cert, self.client_key)
        return ctx

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def health(self) -> Dict[str, Any]:
        return {
            "adapter": "opa",
            "endpoint": self.endpoint,
            "reachable": self._ping_opa(),
            "bundle_loaded": (
                self.bundle_path.exists() if self.bundle_path else False
            ),
            "cache_entries": len(self._cache),
            "cache_ttl_seconds": self.cache_ttl,
            "deadline_seconds": self.deadline_seconds,
            "tls": bool(self._ssl_context),
            "mtls": bool(self.client_cert),
            "authenticated": bool(self.token),
        }

    def _ping_opa(self) -> bool:
        for path in ("/health", "/v1/data/system/info"):
            try:
                req = Request(f"{self.endpoint}{path}",
                              headers=self._headers())
                urlopen(req, timeout=1, context=self._ssl_context)
                return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------
    # bundle (degraded, air-gapped fallback -- NOT a Rego engine)
    # ------------------------------------------------------------------
    def load_bundle(self) -> Optional[Dict]:
        if not self.bundle_path or not self.bundle_path.exists():
            return None
        return json.loads(self.bundle_path.read_text())

    def save_bundle(self, policies: List[Dict],
                    output_path: str = "policies/opa_bundle.json") -> bool:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(policies))
        return True

    def _evaluate_bundle(self, capability: Optional[str]) -> PolicyResult:
        """Degraded evaluation against a local capability allowlist.

        FAIL-CLOSED RULE: the bundle may DENY authoritatively, and may
        clear a capability that is explicitly allowlisted. It may NOT
        conclude 'no policy objection' from silence -- previously a
        capability absent from both lists returned fired=False, which
        the engine skips, silently turning an OPA outage into ALLOW.
        """
        bundle = self.load_bundle()
        if not isinstance(bundle, dict):
            raise PolicyUnavailableError(
                f"policy backend unavailable (opa): {self.endpoint} "
                "unreachable and no usable local bundle"
            )
        denied = bundle.get("denied_capabilities", []) or []
        allowed = bundle.get("allowed_capabilities", []) or []

        if capability and capability in denied:
            return PolicyResult(
                True, "block", "bundle_denied (degraded: OPA unreachable)",
                matched_rule_id=f"bundle:denied:{capability}", degraded=True,
            )
        if capability and capability in allowed:
            return PolicyResult(
                False, "allow",
                "bundle_allowlisted (degraded: OPA unreachable)",
                degraded=True,
            )
        raise PolicyUnavailableError(
            f"policy backend unavailable (opa): {self.endpoint} "
            f"unreachable and the local bundle has no entry for "
            f"capability {capability!r} -- a degraded bundle cannot "
            "authorize by silence"
        )

    # ------------------------------------------------------------------
    # core evaluation
    # ------------------------------------------------------------------
    def check(
        self,
        agent_id: Optional[str] = None,
        capability: Optional[str] = None,
        arguments: Optional[Dict] = None,
        evidence: Optional[Dict] = None,
    ) -> PolicyResult:
        payload = {
            "input": {
                "agent_id": agent_id,
                "capability": capability,
                "arguments": arguments or {},
                "evidence": evidence or {},
            }
        }
        key = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:16]

        cached = self._cache_get(key)
        if cached is not None:
            self._cache_hits += 1
            return PolicyResult(
                cached.fired, cached.outcome,
                f"{cached.reason} (cached)", cached.matched_rule_id,
            )

        self._request_count += 1
        deadline = time.monotonic() + self.deadline_seconds
        backoff = self.DEFAULT_BACKOFF
        last_error: Optional[str] = None

        for attempt in range(1, self.DEFAULT_RETRY_COUNT + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._deadline_exceeded += 1
                last_error = (
                    f"deadline {self.deadline_seconds}s exhausted after "
                    f"{attempt - 1} attempt(s)"
                )
                break
            start = time.monotonic()
            try:
                result = self._call_opa(
                    payload, timeout=min(self.DEFAULT_TIMEOUT, remaining)
                )
                self._update_latency((time.monotonic() - start) * 1000)
                normalized = self._normalize(result)
                self._cache_put(key, normalized)
                return normalized
            except PolicyUnavailableError:
                raise                      # empty/malformed: no retry
            except (URLError, HTTPError, OSError, ValueError) as exc:
                # transient transport/parse failure -- never log
                # capability arguments in failure paths
                last_error = f"{type(exc).__name__}"
                sleep_for = min(backoff, max(0.0, deadline - time.monotonic()))
                if sleep_for > 0:
                    time.sleep(sleep_for)
                backoff *= 2

        # OPA produced nothing within the deadline
        self._fallback_count += 1
        if self.bundle_path:
            return self._evaluate_bundle(capability)
        raise PolicyUnavailableError(
            f"policy backend unavailable (opa): endpoint {self.endpoint} "
            f"produced no verdict within {self.deadline_seconds}s "
            f"({last_error}) and no local bundle is configured"
        )

    def _call_opa(self, payload: Dict, timeout: float) -> Dict:
        req = Request(
            f"{self.endpoint}/v1/data/{self.policy_path}",
            data=json.dumps(payload).encode(),
            headers=self._headers(),
            method="POST",
        )
        with urlopen(req, timeout=timeout, context=self._ssl_context) as resp:
            data = json.loads(resp.read().decode())
            result = data.get("result")
            if not isinstance(result, dict) or not result:
                raise PolicyUnavailableError(
                    f"policy backend unavailable (opa): endpoint "
                    f"{self.endpoint} returned no usable result for "
                    f"policy path {self.policy_path!r}"
                )
            return result

    def _normalize(self, result: Dict) -> PolicyResult:
        fired = bool(result.get("fired", False))
        outcome = result.get("outcome", "allow")
        reason = result.get("reason", "opa_evaluated")
        # Rule identity: whichever key the customer's Rego uses. Absent
        # -> None, and DecisionRecord.policy_id stays honestly null.
        rule_id = (
            result.get("rule_id")
            or result.get("policy_id")
            or result.get("matched_rule_id")
        )
        if fired and outcome not in ("block", "require_approval"):
            raise PolicyUnavailableError(
                f"policy backend returned an unknown outcome "
                f"{outcome!r} for a fired rule -- refusing to interpret"
            )
        return PolicyResult(fired, outcome, reason, rule_id)

    # ------------------------------------------------------------------
    # cache: opt-in, bounded, never caches denials or degraded results
    # ------------------------------------------------------------------
    def _cache_get(self, key: str) -> Optional[PolicyResult]:
        if self.cache_ttl <= 0:
            return None
        entry = self._cache.get(key)
        if entry is None:
            return None
        result, ts = entry
        if (time.time() - ts) >= self.cache_ttl:
            self._cache.pop(key, None)
            return None
        self._cache.move_to_end(key)
        return result

    def _cache_put(self, key: str, result: PolicyResult) -> None:
        # A cached DENIAL would outlive its rule's revocation; a cached
        # DEGRADED result would outlive the outage that produced it.
        if self.cache_ttl <= 0 or result.fired or result.degraded:
            return
        self._cache[key] = (result, time.time())
        self._cache.move_to_end(key)
        while len(self._cache) > self.MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)

    def _update_latency(self, latency_ms: float) -> None:
        if self._avg_latency_ms == 0.0:
            self._avg_latency_ms = latency_ms
        else:
            self._avg_latency_ms = (
                self._avg_latency_ms * 0.9 + latency_ms * 0.1
            )

    def metrics_summary(self) -> Dict:
        return {
            "adapter": "opa",
            "endpoint": self.endpoint,
            "requests": self._request_count,
            "cache_hits": self._cache_hits,
            "fallback_rate": self._fallback_count / max(self._request_count, 1),
            "deadline_exceeded": self._deadline_exceeded,
            "avg_latency_ms": round(self._avg_latency_ms, 2),
            "cache_entries": len(self._cache),
            "cache_ttl_seconds": self.cache_ttl,
            "deadline_seconds": self.deadline_seconds,
            "default_decision": self.default_decision,
            "bundle_loaded": (
                self.bundle_path.exists() if self.bundle_path else False
            ),
            "tls": bool(self._ssl_context),
            "mtls": bool(self.client_cert),
        }
