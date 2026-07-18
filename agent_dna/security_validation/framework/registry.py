"""
Framework registry.

Discovers and instantiates adversaries without coupling the
benchmark runner to concrete implementations.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from agent_dna.security_validation.adversaries.base import BaseAdversary
from agent_dna.security_validation.framework.discovery.loader import discover


class Registry:
    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseAdversary]] = {}

    def discover(self) -> None:
        """Populate registry using existing discovery loader."""
        self._registry.clear()

        for cls in discover():
            self.register(cls)

    def register(self, adversary_cls: Type[BaseAdversary]) -> None:
        self._registry[adversary_cls.__name__] = adversary_cls

    def names(self) -> List[str]:
        return sorted(self._registry.keys())

    def classes(self) -> List[Type[BaseAdversary]]:
        return list(self._registry.values())

    def get(self, name: str) -> Optional[Type[BaseAdversary]]:
        return self._registry.get(name)

    def create(self, name: str) -> BaseAdversary:
        cls = self.get(name)

        if cls is None:
            raise KeyError(f"Unknown adversary: {name}")

        return cls()
