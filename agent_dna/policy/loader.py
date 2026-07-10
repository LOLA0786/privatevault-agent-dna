"""
Policy file loader — YAML or JSON, auto-detected by extension.
Fails loudly with the filename in every error message; never
silently returns an empty or partial policy document.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

import yaml

from .schema import PolicyDocument, parse_policy_dict


def load_policy_file(path: Union[str, Path]) -> PolicyDocument:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    try:
        raw_text = path.read_text()
    except Exception as e:
        raise ValueError(f"could not read policy file {path}: {e}") from e

    if path.suffix in (".yaml", ".yml"):
        try:
            raw = yaml.safe_load(raw_text)
        except yaml.YAMLError as e:
            raise ValueError(f"invalid YAML in policy file {path}: {e}") from e
    elif path.suffix == ".json":
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON in policy file {path}: {e}") from e
    else:
        raise ValueError(
            f"policy file {path} has unrecognized extension "
            f"{path.suffix!r} -- expected .yaml, .yml, or .json"
        )

    if raw is None:
        raise ValueError(f"policy file {path} is empty")

    try:
        return parse_policy_dict(raw)
    except ValueError as e:
        # re-raise with the filename attached for a debuggable error
        raise ValueError(f"policy file {path}: {e}") from e
