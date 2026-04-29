from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class AnalysisRecord:
    password_length: int
    charset_name: str
    charset_size: int
    final_score: float
    rating: str
    dictionary_matched: bool
    dictionary_match_type: str
    dictionary_time_seconds: float
    brute_force_mode: str
    brute_force_estimated_seconds: float
    brute_force_actual_seconds: float | None
    entropy_bits: float


class ResultTracker:
    def __init__(self, storage_path: Path) -> None:
        self._storage_path = storage_path
        self._lock = Lock()
        self._history: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not self._storage_path.exists():
            return []
        try:
            return json.loads(self._storage_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def add(self, record: AnalysisRecord) -> None:
        with self._lock:
            self._history.append(asdict(record))
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._storage_path.write_text(json.dumps(self._history, indent=2), encoding="utf-8")

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._history[-limit:]
