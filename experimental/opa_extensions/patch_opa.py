#!/usr/bin/env python3
"""
Patch agent_dna/adapters_policy/opa.py
...
"""

import shutil
from pathlib import Path

OPA_FILE = Path("agent_dna/adapters_policy/opa.py")

if not OPA_FILE.exists():
    raise SystemExit(f"File not found: {OPA_FILE}")

backup = OPA_FILE.with_suffix(".py.bak")
shutil.copy2(OPA_FILE, backup)

text = OPA_FILE.read_text()

if "from .opa_tls import OPATLSWrapper" not in text:
    anchor = "from urllib.error import URLError, HTTPError"
    replacement = (
        anchor
        + """

from .opa_tls import OPATLSWrapper
from .opa_version import OPAVersionTracker"""
    )
    text = text.replace(anchor, replacement, 1)

marker = "self._avg_latency_ms: float = 0.0"

if marker in text and "self._tls = OPATLSWrapper()" not in text:
    replacement = (
        marker
        + """

        # --------------------------------------------------
        # Optional enterprise extensions (non-breaking)
        # --------------------------------------------------
        self._tls = OPATLSWrapper()
        self._version_tracker = OPAVersionTracker()
        self._version_tracker.load_version(
            str(self.bundle_path) if self.bundle_path else None
        )
"""
    )
    text = text.replace(marker, replacement, 1)

OPA_FILE.write_text(text)

print("Patch applied successfully.")
print(f"Backup created: {backup}")
