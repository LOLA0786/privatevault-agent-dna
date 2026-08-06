from __future__ import annotations

from pathlib import Path

import yaml


class AttackRegistry:
    def __init__(self, root: Path):
        self.root = root
        self.attacks: dict = {}

    def load(self) -> dict:

        for file in self.root.glob("*.yaml"):
            with open(file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            self.attacks[data["id"]] = data

        return self.attacks

    def get(self, attack_id: str):
        return self.attacks.get(attack_id)
