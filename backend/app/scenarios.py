from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import DATA_DIR


class ScenarioRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path or DATA_DIR / "scenarios.json"
        self._scenarios = json.loads(self.path.read_text(encoding="utf-8"))
        self._by_id = {item["id"]: item for item in self._scenarios}

    def all(self) -> list[dict[str, Any]]:
        return self._scenarios

    def public_all(self) -> list[dict[str, Any]]:
        public_keys = ("id", "title", "service", "severity", "summary")
        return [{key: scenario[key] for key in public_keys} for scenario in self._scenarios]

    def get(self, scenario_id: str) -> dict[str, Any] | None:
        return self._by_id.get(scenario_id)
