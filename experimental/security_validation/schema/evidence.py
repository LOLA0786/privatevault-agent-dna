"""
Evidence schema.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class EvidenceObject:
    type: str
    identifier: str
    hash: str = ""
    verified: bool = False
    timestamp: str = ""
    uri: str = ""
    metadata: dict = None

    def to_dict(self):
        return asdict(self)
