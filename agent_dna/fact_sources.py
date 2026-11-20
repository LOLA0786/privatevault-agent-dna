"""Decision facts checked against the system of record (ADR 0045).

Policy rules decide on facts the caller's tool puts in the arguments:
``prior_refunds_for_order``, ``customer_refunds_today``,
``payee_matches_original`` and so on. Probing found three ways that fails:
a refund made outside PrivateVault while an approval waited was not seen
(the approved decide reused facts read before the wait: a Rs 25,000 order was
refunded Rs 30,000); daily counts missed refunds made elsewhere; and a
compromised tool can simply state "no prior refunds".

With ``PV_FACT_SOURCES`` set, the server reads the order's facts itself from
the system of record when a decide would ALLOW or hold for approval, derives
what each declared fact must be for this request, and BLOCKs if the caller's
value differs or the source cannot answer:

    PV_FACT_SOURCES='{"POST /v1/refunds": {"kind": "refund-facts/1",
        "url": "https://payments.internal", "timeout_seconds": 2}}'

The facts are verified, not rewritten: an approval and a permit are bound to
the exact arguments, so a decide whose facts are stale is refused and must be
decided again with fresh ones. A post-approval decide re-reads the source, so
a refund made during the wait is caught.

``refund-facts/1`` is ``GET {url}/v1/orders/{order_id}/refund-facts``:

    {"spec": "refund-facts/1", "order_id": ..., "customer_id": ...,
     "amount": <int>, "paid_with": ..., "refunds": [{"amount": <int>}, ...],
     "customer_refunds_today": <int>, "customer_amount_today": <int>}

404 means the order is unknown. The facts derived for an action with
``amount`` and ``payee``: ``customer_id``, ``original_amount``,
``original_payee``, ``amount_exceeds_original``, ``payee_matches_original``,
``prior_refunds_for_order``, ``customer_refunds_today``,
``customer_amount_today_after``. ``verify`` (default: all of them) names the
ones the caller must carry and get right.

What this does not do: it trusts the source. A fact can still change between
this read and the payment; the receiver's transaction key (ADR 0040) and the
reservation (ADR 0041) handle a second payment for the same refund, nothing
handles a refund made elsewhere in that window.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SOURCES_ENV = "PV_FACT_SOURCES"
KIND_REFUND = "refund-facts/1"
TRIGGERED_BY_FACTS = "fact_verification"
FACTS_MISMATCH = "FACTS_MISMATCH"
FACTS_UNAVAILABLE = "FACTS_UNAVAILABLE"
FACTS_ORDER_UNKNOWN = "FACTS_ORDER_UNKNOWN"
FACTS_INPUT_MISSING = "FACTS_INPUT_MISSING"

REFUND_FACTS = (
    "customer_id",
    "original_amount",
    "original_payee",
    "amount_exceeds_original",
    "payee_matches_original",
    "prior_refunds_for_order",
    "customer_refunds_today",
    "customer_amount_today_after",
)
_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_KEYS = {"kind", "url", "timeout_seconds", "verify", "order_field"}


class FactSourceConfigError(ValueError):
    """``PV_FACT_SOURCES`` is malformed. The server does not start."""


@dataclass(frozen=True)
class FactSource:
    operation: str
    kind: str
    url: str
    timeout_seconds: float
    verify: tuple[str, ...]
    order_field: str = "order_id"


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str


def sources_from_env(env: Mapping[str, str]) -> dict[str, FactSource]:  # noqa: C901 - checklist
    raw = str(env.get(SOURCES_ENV, "") or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise FactSourceConfigError(f"{SOURCES_ENV} is not JSON: {exc}") from None
    if not isinstance(value, dict) or not value:
        raise FactSourceConfigError(f'{SOURCES_ENV} must map "METHOD path" to a source')
    sources: dict[str, FactSource] = {}
    for operation, spec in value.items():
        method, _, path = str(operation).partition(" ")
        if method not in _METHODS or not path.startswith("/") or " " in path:
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation!r} is not a write operation"
            )
        if not isinstance(spec, dict) or not set(spec) <= _KEYS:
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: keys are {sorted(_KEYS)}"
            )
        if spec.get("kind") != KIND_REFUND:
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: kind must be {KIND_REFUND!r}"
            )
        url = spec.get("url")
        parsed = urllib.parse.urlparse(url if isinstance(url, str) else "")
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: url must be http(s)://host"
            )
        timeout = spec.get("timeout_seconds", 2)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 10
        ):
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: timeout_seconds must be in (0, 10]"
            )
        verify = spec.get("verify", list(REFUND_FACTS))
        if (
            not isinstance(verify, list)
            or not verify
            or not set(verify) <= set(REFUND_FACTS)
        ):
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: verify must list some of {list(REFUND_FACTS)}"
            )
        order_field = spec.get("order_field", "order_id")
        if not isinstance(order_field, str) or not order_field:
            raise FactSourceConfigError(
                f"{SOURCES_ENV}: {operation}: order_field must be a name"
            )
        sources[str(operation)] = FactSource(
            operation=str(operation),
            kind=KIND_REFUND,
            url=str(url).rstrip("/"),
            timeout_seconds=float(timeout),
            verify=tuple(verify),
            order_field=order_field,
        )
    return sources


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def fetch_refund_record(source: FactSource, order_id: str) -> dict[str, Any] | Finding:
    url = f"{source.url}/v1/orders/{urllib.parse.quote(order_id, safe='')}/refund-facts"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(
            request, timeout=source.timeout_seconds
        ) as response:
            record = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Finding(
                FACTS_ORDER_UNKNOWN, f"the system of record has no order {order_id!r}"
            )
        return Finding(FACTS_UNAVAILABLE, f"the system of record answered {exc.code}")
    except (OSError, ValueError) as exc:
        return Finding(
            FACTS_UNAVAILABLE,
            f"the system of record could not be read: {type(exc).__name__}",
        )
    if (
        not isinstance(record, dict)
        or record.get("spec") != KIND_REFUND
        or record.get("order_id") != order_id
        or not isinstance(record.get("customer_id"), str)
        or not _integer(record.get("amount"))
        or not isinstance(record.get("paid_with"), str)
        or not isinstance(record.get("refunds"), list)
        or not all(
            isinstance(r, dict) and _integer(r.get("amount")) for r in record["refunds"]
        )
        or not _integer(record.get("customer_refunds_today"))
        or not _integer(record.get("customer_amount_today"))
    ):
        return Finding(
            FACTS_UNAVAILABLE, f"the system of record's answer is not {KIND_REFUND}"
        )
    return record


def derive_refund_facts(
    record: Mapping[str, Any], amount: int, payee: str
) -> dict[str, Any]:
    """What each fact must be for refunding ``amount`` to ``payee`` now."""
    return {
        "customer_id": record["customer_id"],
        "original_amount": record["amount"],
        "original_payee": record["paid_with"],
        "amount_exceeds_original": amount > record["amount"],
        "payee_matches_original": payee == record["paid_with"],
        "prior_refunds_for_order": len(record["refunds"]),
        "customer_refunds_today": record["customer_refunds_today"],
        "customer_amount_today_after": record["customer_amount_today"] + amount,
    }


def check_facts(source: FactSource, arguments: Mapping[str, Any]) -> Finding | None:
    """None when every declared fact in ``arguments`` matches the system of
    record; otherwise why the decide must not stand."""
    order_id = arguments.get(source.order_field)
    amount = arguments.get("amount")
    payee = arguments.get("payee")
    if (
        not isinstance(order_id, str)
        or not order_id
        or isinstance(amount, bool)
        or not isinstance(amount, int)
        or not isinstance(payee, str)
    ):
        return Finding(
            FACTS_INPUT_MISSING,
            f"{source.operation} is checked against the system of record and the "
            f"action lacks a {source.order_field}, an integer amount or a payee",
        )
    record = fetch_refund_record(source, order_id)
    if isinstance(record, Finding):
        return record
    truth = derive_refund_facts(record, amount, payee)
    wrong = [
        f"{name}: stated {arguments.get(name, '(missing)')!r}, system of record {truth[name]!r}"
        for name in source.verify
        if name not in arguments
        or arguments[name] != truth[name]
        or type(arguments[name]) is not type(truth[name])
    ]
    if wrong:
        return Finding(
            FACTS_MISMATCH,
            "facts differ from the system of record (stale, or not true): "
            + "; ".join(wrong)
            + ". Decide again with facts read now",
        )
    return None


def sources_manifest(sources: Mapping[str, FactSource]) -> dict[str, Any]:
    return {
        "enabled": bool(sources),
        "operations": {
            op: {"kind": s.kind, "url": s.url, "verify": list(s.verify)}
            for op, s in sorted(sources.items())
        },
    }
