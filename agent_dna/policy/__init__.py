"""
Customer-configurable policy layer. Rules are data (YAML/JSON), not
hardcoded Python -- the direct answer to 'how does your system know
this is our company's policy': load a PolicyDocument from a customer
file, attach a PolicyChecker to the engine.
"""

from .checker import PolicyChecker, PolicyCheckResult
from .loader import load_policy_file
from .schema import PolicyCondition, PolicyDocument, PolicyRule, parse_policy_dict

__all__ = [
    "PolicyChecker",
    "PolicyCheckResult",
    "PolicyDocument",
    "PolicyRule",
    "PolicyCondition",
    "parse_policy_dict",
    "load_policy_file",
]
