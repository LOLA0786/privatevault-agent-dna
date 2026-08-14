#!/usr/bin/env python3
"""Idempotent Fineract lab seed. Stdlib only. No mocks.

Creates two clients and three savings accounts (A funded, B and C empty).
The brief asked for two accounts; case 1 mutates the destination to C, so
C is seeded here. Fails loudly if any response is missing expected keys.

TLS: compose tlsgen writes tls/cert.pem with SAN DNS:localhost and
IP:127.0.0.1. Requests verify that pin with check_hostname on.
ssl._create_unverified_context is not used.
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
from datetime import date
from http.client import HTTPSConnection
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CERT_PATH = HERE / "fineract-dev.pem"
COMPOSE_CERT = HERE / "tls" / "cert.pem"
STATE_PATH = HERE / "seed-state.json"

HOST = "localhost"
PORT = 8443
BASE = "/fineract-provider/api/v1"
TENANT_HEADER = "Fineract-Platform-TenantId"
TENANT_ID = "default"
USERNAME = "mifos"
PASSWORD = "password"
SAVINGS_ACCOUNT_TYPE = 2  # AccountTransfersApiResource template: fromAccountType=2

CLIENT_A_EXT = "pv-pilot-client-a"
CLIENT_B_EXT = "pv-pilot-client-b"
ACCOUNT_A_EXT = "pv-pilot-savings-a"
ACCOUNT_B_EXT = "pv-pilot-savings-b"
ACCOUNT_C_EXT = "pv-pilot-savings-c"
PRODUCT_NAME = "PV Pilot Savings"
FUND_AMOUNT = "10000"


class ShapeError(RuntimeError):
    """API JSON did not match the keys this seed requires."""


def _format_business_date(value: Any) -> str:
    """Jackson LocalDate on 1.11.0 is [year, month, day]."""
    if not (isinstance(value, list) and len(value) >= 3):
        raise ShapeError(
            f"GET /businessdate date is not [year, month, day]: {value!r}. "
            "If a deposit is rejected as future-dated, the organisation "
            "business date (GET /v1/businessdate) is the likely cause."
        )
    try:
        return date(int(value[0]), int(value[1]), int(value[2])).strftime("%d %B %Y")
    except (TypeError, ValueError) as exc:
        raise ShapeError(
            f"GET /businessdate date {value!r} is not a calendar day: {exc}. "
            "If a deposit is rejected as future-dated, the organisation "
            "business date is the likely cause."
        ) from exc


def business_date_string(api: Fineract) -> str:
    """Organisation BUSINESS_DATE, not the client clock.

    A later calendar day with a frozen container date rejects a
    client-clock 'today' as a future-dated transaction.
    """
    data = api.request("GET", f"{BASE}/businessdate")
    if not isinstance(data, list):
        raise ShapeError(
            f"GET /businessdate expected list, got {type(data).__name__}: {data!r}"[:800]
            + " If a deposit is rejected as future-dated, the organisation "
            "business date is the likely cause."
        )
    chosen = None
    for item in data:
        rec = _require(item, "type", "date")
        if rec["type"] == "BUSINESS_DATE":
            chosen = rec["date"]
            break
    if chosen is None:
        raise ShapeError(
            "GET /businessdate has no type BUSINESS_DATE. "
            "If a deposit is rejected as future-dated, the organisation "
            f"business date is the likely cause. raw={data!r}"[:2000]
        )
    return _format_business_date(chosen)


def _require(obj: Any, *keys: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ShapeError(f"expected object, got {type(obj).__name__}: {obj!r}")
    missing = [k for k in keys if k not in obj]
    if missing:
        raise ShapeError(f"missing keys {missing} in {sorted(obj.keys())}: {obj!r}"[:2000])
    return obj


def _pem_body(pem: str) -> str:
    return "".join(line.strip() for line in pem.splitlines() if "-----" not in line)


def ssl_context(cafile: Path | None = None) -> ssl.SSLContext:
    """Pinned lab cert, hostname checking on.

    The compose cert SAN covers DNS:localhost and IP:127.0.0.1, so
    check_hostname stays enabled. Do not set check_hostname = False.
    """
    pin = cafile or COMPOSE_CERT
    if not pin.is_file():
        raise SystemExit(
            f"TLS pin {pin} is missing. From pilot/fineract run: docker compose up -d"
        )
    ctx = ssl.create_default_context(cafile=str(pin))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def pin_cert() -> ssl.SSLContext:
    if not COMPOSE_CERT.is_file():
        raise SystemExit(
            f"{COMPOSE_CERT} is missing. From pilot/fineract run: docker compose up -d"
        )
    pinned = COMPOSE_CERT.read_text(encoding="utf-8")
    presented = ssl.get_server_certificate((HOST, PORT))
    if _pem_body(presented) != _pem_body(pinned):
        raise SystemExit(
            "live server certificate does not match compose-generated "
            f"{COMPOSE_CERT}. Recreate the stack: docker compose down -v "
            "&& docker compose up -d"
        )
    CERT_PATH.write_text(pinned, encoding="utf-8")
    return ssl_context(COMPOSE_CERT)


class Fineract:
    def __init__(self, ctx: ssl.SSLContext) -> None:
        self.ctx = ctx
        token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode("ascii")
        self.headers = {
            "Authorization": f"Basic {token}",
            TENANT_HEADER: TENANT_ID,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        conn = HTTPSConnection(HOST, PORT, context=self.ctx, timeout=60)
        try:
            conn.request(method, path, body=payload, headers=self.headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()
        if status not in expected:
            raise ShapeError(f"{method} {path} -> HTTP {status}, body={raw[:2000]!r}")
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ShapeError(f"{method} {path} not JSON: {raw[:500]!r}") from exc
        if status == 404:
            return None
        return parsed


def wait_up(ctx: ssl.SSLContext) -> None:
    conn = HTTPSConnection(HOST, PORT, context=ctx, timeout=10)
    try:
        conn.request("GET", "/fineract-provider/actuator/health")
        resp = conn.getresponse()
        raw = resp.read()
        status = resp.status
    except OSError as exc:
        raise SystemExit(
            f"Fineract is not reachable at https://{HOST}:{PORT}: {exc}. "
            "docker compose up -d, wait until healthy, then re-run."
        ) from exc
    finally:
        conn.close()
    if status != 200:
        raise SystemExit(f"health HTTP {status}: {raw!r}")


def find_client(api: Fineract, external_id: str) -> int | None:
    data = api.request(
        "GET",
        f"{BASE}/clients/external-id/{external_id}",
        expected=(200, 404),
    )
    if data is None:
        return None
    return int(_require(data, "id")["id"])


def create_client(
    api: Fineract, external_id: str, first: str, last: str, on_date: str
) -> int:
    existing = find_client(api, external_id)
    if existing is not None:
        return existing
    data = api.request(
        "POST",
        f"{BASE}/clients",
        {
            "officeId": 1,
            "legalFormId": 1,
            "firstname": first,
            "lastname": last,
            "externalId": external_id,
            "active": True,
            "activationDate": on_date,
            "submittedOnDate": on_date,
            "dateFormat": "dd MMMM yyyy",
            "locale": "en",
        },
    )
    return int(_require(data, "clientId")["clientId"])


def ensure_product(api: Fineract) -> int:
    data = api.request("GET", f"{BASE}/savingsproducts")
    if not isinstance(data, list):
        raise ShapeError(f"GET /savingsproducts expected list, got {type(data)}: {data!r}"[:800])
    for item in data:
        rec = _require(item, "id", "name")
        if rec["name"] == PRODUCT_NAME:
            return int(rec["id"])
    created = api.request(
        "POST",
        f"{BASE}/savingsproducts",
        {
            "name": PRODUCT_NAME,
            "shortName": "PVS",
            "currencyCode": "USD",
            "digitsAfterDecimal": 2,
            "inMultiplesOf": 1,
            "locale": "en",
            "nominalAnnualInterestRate": 0,
            "interestCompoundingPeriodType": 1,
            "interestPostingPeriodType": 4,
            "interestCalculationType": 1,
            "interestCalculationDaysInYearType": 365,
            "accountingRule": 1,
        },
    )
    return int(_require(created, "resourceId")["resourceId"])


def find_savings(api: Fineract, external_id: str) -> int | None:
    data = api.request(
        "GET",
        f"{BASE}/savingsaccounts/external-id/{external_id}",
        expected=(200, 404),
    )
    if data is None:
        return None
    return int(_require(data, "id")["id"])


def _savings_status(api: Fineract, account_id: int) -> dict[str, Any]:
    data = api.request("GET", f"{BASE}/savingsaccounts/{account_id}")
    rec = _require(data, "id", "status")
    return _require(rec["status"], "active", "approved", "submittedAndPendingApproval")


def activate_savings(api: Fineract, account_id: int, on_date: str) -> None:
    status = _savings_status(api, account_id)
    if status["active"]:
        return
    if status["submittedAndPendingApproval"] or not status["approved"]:
        api.request(
            "POST",
            f"{BASE}/savingsaccounts/{account_id}?command=approve",
            {
                "locale": "en",
                "dateFormat": "dd MMMM yyyy",
                "approvedOnDate": on_date,
            },
        )
    status = _savings_status(api, account_id)
    if status["active"]:
        return
    api.request(
        "POST",
        f"{BASE}/savingsaccounts/{account_id}?command=activate",
        {
            "locale": "en",
            "dateFormat": "dd MMMM yyyy",
            "activatedOnDate": on_date,
        },
    )
    status = _savings_status(api, account_id)
    if not status["active"]:
        raise ShapeError(f"savings {account_id} is not active after approve/activate: {status}")


def create_savings(
    api: Fineract, client_id: int, product_id: int, external_id: str, on_date: str
) -> int:
    existing = find_savings(api, external_id)
    if existing is not None:
        activate_savings(api, existing, on_date)
        return existing
    data = api.request(
        "POST",
        f"{BASE}/savingsaccounts",
        {
            "clientId": client_id,
            "productId": product_id,
            "locale": "en",
            "dateFormat": "dd MMMM yyyy",
            "submittedOnDate": on_date,
            "externalId": external_id,
        },
    )
    account_id = int(_require(data, "savingsId")["savingsId"])
    activate_savings(api, account_id, on_date)
    return account_id


def account_snapshot(api: Fineract, account_id: int) -> dict[str, Any]:
    data = api.request(
        "GET",
        f"{BASE}/savingsaccounts/{account_id}?associations=transactions",
    )
    rec = _require(data, "id", "summary")
    summary = _require(rec["summary"], "accountBalance")
    transactions = rec.get("transactions")
    if transactions is not None and not isinstance(transactions, list):
        raise ShapeError(f"transactions is not a list: {type(transactions)}")
    return {
        "id": int(rec["id"]),
        "accountBalance": str(summary["accountBalance"]),
        "transaction_count": 0 if transactions is None else len(transactions),
    }


def payment_type_id_for_deposit(api: Fineract) -> int:
    """Non-system-defined payment type for a savings deposit.

    Live 1.11.0: type 1 is "Money Transfer" (isSystemDefined false).
    Types 2 and 3 are system-defined loan adjustments — do not use them.
    Id 1 is not hardcoded; it is selected by this lookup.
    """
    data = api.request("GET", f"{BASE}/paymenttypes")
    if not isinstance(data, list):
        raise ShapeError(
            f"GET /paymenttypes expected list, got {type(data)}: {data!r}"[:800]
        )
    usable: list[int] = []
    for item in data:
        rec = _require(item, "id", "isSystemDefined")
        if rec["isSystemDefined"] is False:
            usable.append(int(rec["id"]))
    if not usable:
        raise ShapeError(
            "GET /paymenttypes has no non-system-defined type "
            "(isSystemDefined=false). Deposit cannot proceed. "
            f"raw={data!r}"[:2000]
        )
    return min(usable)


def fund_if_needed(
    api: Fineract, account_id: int, payment_type_id: int, on_date: str
) -> None:
    snap = account_snapshot(api, account_id)
    if float(snap["accountBalance"]) >= float(FUND_AMOUNT):
        return
    try:
        result = api.request(
            "POST",
            f"{BASE}/savingsaccounts/{account_id}/transactions?command=deposit",
            {
                "paymentTypeId": payment_type_id,
                "transactionDate": on_date,
                "transactionAmount": FUND_AMOUNT,
                "dateFormat": "dd MMMM yyyy",
                "locale": "en",
            },
        )
    except ShapeError as exc:
        raise ShapeError(
            f"{exc} Likely cause: transactionDate is not the organisation "
            "business date (GET /v1/businessdate, type BUSINESS_DATE). "
            "A client-clock date can be ahead of the container."
        ) from exc
    rec = _require(result, "officeId", "clientId", "savingsId", "resourceId", "changes")
    _require(rec["changes"], "paymentTypeId")


def main() -> int:
    try:
        ctx = pin_cert()
        wait_up(ctx)
        api = Fineract(ctx)
        office = api.request("GET", f"{BASE}/offices/1")
        _require(office, "id")
        on_date = business_date_string(api)
        product_id = ensure_product(api)
        client_a = create_client(api, CLIENT_A_EXT, "Pilot", "Alpha", on_date)
        client_b = create_client(api, CLIENT_B_EXT, "Pilot", "Beta", on_date)
        account_a = create_savings(api, client_a, product_id, ACCOUNT_A_EXT, on_date)
        account_b = create_savings(api, client_b, product_id, ACCOUNT_B_EXT, on_date)
        account_c = create_savings(api, client_b, product_id, ACCOUNT_C_EXT, on_date)
        payment_type_id = payment_type_id_for_deposit(api)
        fund_if_needed(api, account_a, payment_type_id, on_date)
        snaps = {
            "A": account_snapshot(api, account_a),
            "B": account_snapshot(api, account_b),
            "C": account_snapshot(api, account_c),
        }
        state = {
            "base": f"https://{HOST}:{PORT}{BASE}",
            "tenant_header": TENANT_HEADER,
            "tenant_id": TENANT_ID,
            "office_id": 1,
            "product_id": product_id,
            "client_a_id": client_a,
            "client_b_id": client_b,
            "account_a_id": account_a,
            "account_b_id": account_b,
            "account_c_id": account_c,
            "account_type_savings": SAVINGS_ACCOUNT_TYPE,
            "payment_type_id": payment_type_id,
            "business_date": on_date,
            "balances": {k: v["accountBalance"] for k, v in snaps.items()},
            "snapshots": snaps,
            "cert": str(CERT_PATH),
        }
        STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(state, indent=2))
        return 0
    except ShapeError as exc:
        print(f"FINERACT API SHAPE CHANGED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
