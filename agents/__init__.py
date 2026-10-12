"""Customised agents built on PrivateVault.

``agents/core`` is the template: a model proposes tool calls, every money or
external action is decided by PrivateVault (``/v1/decide``), escalations are
settled by a signed human approval (ADR 0020), money actions are minted into
a single-use permit (``/v1/authorize``) and dispatched through the exact-byte
sidecar to a receiver gate (ADR 0019). ``agents/personas/*`` are YAML plus a
tool list; none of them change core code. Not shipped in the wheel.
"""
