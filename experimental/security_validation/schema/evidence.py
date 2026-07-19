"""
Evidence schema.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class EvidenceObject:
    type: str
    identifier: str
    hash: str = ""
    verified: bool = False
    timestamp: str = ""
    uri: str = ""
    metadata: Dict = None

    def to_dict(self):
        return asdict(self)
