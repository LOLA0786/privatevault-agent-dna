"""
Vendored from UAAL's Enterprise Action Verification (EAV) engine.
Origin: ~/UAAL/eav/ (commit c30948d). UAAL remains the home repo;
this copy exists so the composed decision line has no cross-repo
filesystem dependency. Sync deliberately, not automatically.
"""
from .invariant_engine import Invariant, InvariantEngine

__all__ = ["Invariant", "InvariantEngine"]
