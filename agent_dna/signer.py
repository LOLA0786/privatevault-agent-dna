"""
Runtime signer selector.

All existing imports continue working.

Switch implementations using:

export PV_USE_RUST_SIGNER=1
"""

from __future__ import annotations

import os

USE_RUST = (
    os.getenv("PV_USE_RUST_SIGNER", "0").lower()
    in ("1", "true", "yes")
)

if USE_RUST:

    from .signer_bridge import *

else:

    from .signer_python import *
