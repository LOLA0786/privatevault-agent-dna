# 0027: The receiver kit is hardened by default

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/network/test_receiver_hardened.py::test_plaintext_needs_an_explicit_flag;
            tests/network/test_receiver_hardened.py::test_revocation_source_is_required;
            tests/network/test_receiver_hardened.py::test_gate_refuses_everything_until_a_list_is_installed;
            tests/network/test_receiver_hardened.py::test_unreachable_api_ends_in_refusals_not_admissions;
            tests/network/test_receiver_hardened.py::test_mtls_requires_presenters_by_default

## What forced the decision
An external review (19 October 2026, finding 4) found that the receiver kit
was not a hardened deployment unless the operator knew which pieces to
assemble. Its image served plain HTTP (`uvicorn`), so presenters could not
be authenticated. Its gate constructor never attached the signed revocation
list that the gate and the API both supported. And nothing required a
presenter even when mTLS was on.

## The decision
The kit's defaults are the hardened deployment, and each relaxation is an
explicit flag that the start-up summary names:

- **Mutual TLS only.** Without `PV_RECEIVER_TLS_CERT`, `PV_RECEIVER_TLS_KEY`
  and `PV_RECEIVER_CLIENT_CA` the gate does not start.
  `PV_RECEIVER_ALLOW_PLAINTEXT=1` serves plain HTTP for a local demo. The
  image runs `serve.py`. The `uvicorn` entry point (`app.py`) refuses TLS
  settings it cannot honour.
- **Presenters required with mTLS.** A permit that does not name its
  presenter (spec 0.1) is refused unless `PV_RECEIVER_REQUIRE_PRESENTER=0`.
- **Revocation list required, fail closed.** `PV_REVOCATION_URL` (the API's
  `GET /v1/revocations`) and `PV_REVOCATION_API_KEY_FILE` (an audit-scope
  key) are required unless `PV_RECEIVER_ALLOW_NO_REVOCATION=1`. `build_gate`
  attaches the list cache. `network/receiver_kit/revocations.py` fetches
  every `PV_REVOCATION_REFRESH_SECONDS` (default 10), verifies the list
  against the pinned trust bundle and installs it. Until a list is
  installed, and once it passes `next_update`, every permit is refused with
  503 `RECEIVER_REVOCATION_LIST_STALE`. A failed fetch changes nothing. The
  list URL must be https unless `PV_ALLOW_HTTP_REVOCATION=1`.
- **Secrets reach the gate user.** The entrypoint hands the TLS key and the
  revocation API key to the gate user the same way as the receipt key: a
  0400 copy in tmpfs, root dropped before exec.
- **One receiver host.** The ledger is SQLite. The start-up summary says
  so, and the reference deployment runs one replica.

The demo compose file sets the plaintext and no-revocation flags under a
"LOCAL DEMO ONLY" comment.

## What this costs us
- An existing deployment that started the image without TLS settings stops
  starting. It must add TLS material or set the demo flag on purpose.
- The receiver depends on the PrivateVault API being reachable. If the API
  is unreachable for longer than the list's validity (30 seconds by
  default, `PV_REVOCATION_LIST_TTL_SECONDS`), the receiver admits nothing.
  That is the intended failure mode.
- The receiver holds an audit-scope API key for the issuer's API.

## Not decided here
The API's secure profile does not yet require a presenter bundle. Permits
from a deployment without one are spec 0.1 and are refused by a gate with
default settings. Requiring the bundle needs agent client-certificate
provisioning in `tools/init_secure_profile.py`; that is the next change. A
receiver ledger on PostgreSQL, for receiver replicas on several hosts, is a
later Phase 1 item.
