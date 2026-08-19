# Campfire black-box (internal)

Hosted evaluation for one design partner. Campfire gets a URL, a scoped key delivered out of band, and `partner-pack/`. They do not get this repository, a source-bearing image, signing keys, or the database.

Build the partner zip with:

```bash
uv run python tools/build_campfire_partner_pack.py
```

Bootstrap a local runtime directory with:

```bash
uv run python tools/init_campfire_blackbox.py --out deploy/partners/campfire-blackbox/runtime
```

`INTERNAL-DEPLOYMENT.md` stays here. It is not in the zip.
