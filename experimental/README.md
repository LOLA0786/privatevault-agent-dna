# Experimental — quarantined from the production package

Nothing in this directory is part of the installable `agent_dna`
package, the production enforcement path, or any compliance claim.
Code lands here when it exists in the tree but does not meet the
engineering standard (docs/ENGINEERING-STANDARD.md) — typically
placeholders, stubs, or harnesses whose results are not independently
verifiable.

Current contents and why:

* `security_validation/` + `run_security_suite.py` — adversarial
  "benchmark" whose adversaries grade themselves: JailbreakAgent.run()
  and RogueMCPAgent return "BLOCKED" and perfect scores WITHOUT
  invoking the runtime; the replay adversary decides success via its
  own timestamp arithmetic. These results are not evidence of
  anything. Rebuild rule before this returns to the package: an
  attack case must issue a real request to the real runtime, the
  verdict must come from the runtime, evidence must be persisted and
  independently verified, and NO adversary may declare itself
  blocked. (The honest adversarial harness is tools/run_adversarial.py
  against spec/adversarial/, which exercises the actual engine.)
* `opa_extensions/` — cluster health_check_all() returns a prefilled
  dict without contacting anything; TLS wrapper accepts a certificate
  pin and never validates it; version tracker hashes a constant;
  patch_opa.py edits source files at import time. The production OPA
  adapter (agent_dna/adapters_policy/opa.py) is NOT here — it is
  real, fail-closed, and tested.
* `marketplace/` — network-effects layer whose profile_export module
  is empty, breaking the package import. Roadmap, not product.
* `postgres_cluster.py` — write() always returns True, read() always
  returns []. A store that acknowledges writes it never performs is
  the opposite of this product.

`tests/test_quarantine.py` enforces that none of this is importable
from the shipped package.
