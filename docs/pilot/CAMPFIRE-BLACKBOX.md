# Campfire hosted black-box evaluation

Design-partner pack for a source-free hosted interface. Campfire receives `deploy/partners/campfire-blackbox/partner-pack/` (zipped) plus a URL and a scoped API key delivered separately.

They do not receive this repository, runtime source, a source-bearing image, git history, signing private keys, the API-key registry, credentials, or database files.

Operator steps: `docs` here, `INTERNAL-DEPLOYMENT.md` next to the pack, `tools/init_campfire_blackbox.py`, `tools/build_campfire_partner_pack.py`, `tools/smoke_campfire_blackbox.py`.

Named tests: `tests/test_campfire_blackbox.py`.

This evaluation does not prove that Campfire's real tool path is mediated until that path is routed through the dispatcher.

Replay refusal and byte-mutation refusal are demonstrated by `tools/adversarial_egress_demo.py` (recording transport). That is not a partner-executable live dispatch test unless Campfire routes its real tool execution through the PrivateVault dispatcher.
