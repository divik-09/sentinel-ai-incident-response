from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import DATA_DIR

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


class RunbookRetriever:
    """Small transparent lexical retriever; no external vector database required."""

    def __init__(self, path: Path | None = None):
        self.runbooks = json.loads((path or DATA_DIR / "runbooks.json").read_text(encoding="utf-8"))

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(_TOKEN_RE.findall(text.lower()))

    def search(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        query_tokens = self._tokens(query)
        scored: list[tuple[float, dict[str, Any]]] = []
        for runbook in self.runbooks:
            searchable = " ".join([runbook["title"], *runbook.get("tags", []), *runbook.get("symptoms", []), *runbook.get("steps", [])])
            tokens = self._tokens(searchable)
            overlap = query_tokens & tokens
            # Normalized overlap makes this deterministic and explainable for a small runbook set.
            score = len(overlap) / max(1, len(query_tokens))
            title_tokens = self._tokens(runbook["title"])
            score += 0.15 * len(query_tokens & title_tokens)
            if score > 0:
                scored.append((score, {**runbook, "retrieval_score": round(min(score, 1.0), 3)}))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [item for _, item in scored[:limit]]
