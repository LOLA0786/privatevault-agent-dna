"""
Policy Adapter Layer — consumes existing enterprise policies
without requiring migration.

Adapters:
- local (SQLite / PostgreSQL profile store)
- git (CI/CD policy bundle)
- opa (Open Policy Agent)
- azure_iam / aws_iam (future)
"""

from .local import LocalPolicyAdapter
from .opa import OPAPolicyAdapter

__all__ = ["LocalPolicyAdapter", "OPAPolicyAdapter", "SkillAdapter"]

from .skill_adapter import SkillAdapter
