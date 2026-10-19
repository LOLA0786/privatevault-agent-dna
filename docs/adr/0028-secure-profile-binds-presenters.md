# 0028: The secure profile binds every permit to its presenter

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/test_secure_profile_presenters.py::test_secure_profile_needs_a_presenter_bundle;
            tests/test_secure_profile_presenters.py::test_secure_mint_requires_the_agents_own_presenter;
            tests/test_secure_profile_presenters.py::test_default_receiver_admits_only_the_bound_agent;
            tests/test_secure_profile_presenters.py::test_provision_issues_and_pins_client_certificates;
            tests/test_secure_profile_presenters.py::test_chart_requires_a_presenter_bundle_with_the_secure_profile

## What forced the decision
An external review (19 October 2026, finding 4) noted that the secure
profile did not require presenter keys. Without `PV_PRESENTER_BUNDLE` the
API minted spec 0.1 permits. Anyone holding a permit and its bytes could
present it. A receiver with the kit's default settings (ADR 0027) refuses
such permits, so the two defaults did not work together.

## The decision
- Under `PV_SECURE_PROFILE` the API does not start without
  `PV_PRESENTER_BUNDLE`. It also refuses to start if the bundle's
  organisation differs from the trust bundle's. Every mint then requires
  `presenter_identity_digest` pinned for that agent (ADR 0022), and every
  permit is spec 0.2.
- `tools/init_secure_profile.py` issues the material:
  - a client CA (`presenters/client-ca.pem`, key 0600);
  - one EC P-256 client certificate per API-key holder (`clientAuth`, one
    year, key 0600);
  - `presenter-bundle.json`, which pins each certificate's key.

  `secure.env` sets `PV_PRESENTER_BUNDLE`. Receivers use `client-ca.pem` as
  `PV_RECEIVER_CLIENT_CA`.
- The Helm chart refuses to render with the secure profile and no
  `config.presenterBundleKey`. The CI values and the kind install supply
  it.
- `cryptography` becomes a declared dependency. It was already installed
  through `mcp` (`pyjwt[crypto]`).

## What this costs us
- Every agent that mints under the secure profile needs its own client
  certificate in its sidecar. Integrations that minted without one are
  refused with `AUTHORIZE_PRESENTER_REQUIRED`.
- Certificates expire after a year. Renewal means issuing a new one with
  the client CA and updating the presenter bundle; there is no automation
  yet.
- The client CA key sits beside the other material after provisioning. The
  operator should move it offline.

## What would make us revisit
An existing enterprise PKI (then the bundle pins its certificates and this
tool only builds the bundle), or automated renewal through a certificate
manager.
