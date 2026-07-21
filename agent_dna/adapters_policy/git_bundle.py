"""DEPRECATED shim — GitBundleAdapter is experimental, not core.

The sketch now lives in ``experimental/adapters/git_bundle.py`` and is
NOT part of the enforced decision path. This shim keeps old imports
working while making the boundary impossible to miss.
"""

import warnings

from experimental.adapters.git_bundle import GitBundleAdapter  # noqa: F401

warnings.warn(
    "GitBundleAdapter is EXPERIMENTAL and not part of the enforced core; "
    "import from experimental.adapters.git_bundle (this shim will be "
    "removed).",
    DeprecationWarning,
    stacklevel=2,
)
