"""
Automatic adversary discovery.

Discovers every subclass of BaseAdversary inside
agent_dna.security_validation.adversaries.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import agent_dna.security_validation.adversaries as adversaries_pkg
from agent_dna.security_validation.adversaries.base import BaseAdversary


def discover():
    discovered = []

    for _, module_name, _ in pkgutil.iter_modules(adversaries_pkg.__path__):
        if module_name.startswith("_"):
            continue

        if module_name == "base":
            continue

        module = importlib.import_module(f"{adversaries_pkg.__name__}.{module_name}")

        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, BaseAdversary) and cls is not BaseAdversary:
                discovered.append(cls)

    return discovered
