from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from zxcvbn import zxcvbn as _zxcvbn
except Exception:  # pragma: no cover
    _zxcvbn = None


@dataclass(frozen=True)
class ZxcvbnResult:
    score: float
    raw_score: int
    guesses: float
    crack_time_seconds: float | None
    feedback: str


def analyze(password: str) -> ZxcvbnResult:
    if not password:
        return ZxcvbnResult(0.0, 0, 0.0, None, "Empty password")

    if _zxcvbn is None:
        length_score = min(len(password) * 8, 100)
        return ZxcvbnResult(float(length_score), min(round(length_score / 25), 4), float(len(password)), None, "zxcvbn unavailable")

    result: dict[str, Any] = _zxcvbn(password)
    raw_score = int(result.get("score", 0))
    normalized_score = (raw_score / 4) * 100
    guesses = float(result.get("guesses", 0.0))
    crack_times = result.get("crack_times_seconds", {}) or {}
    crack_time_seconds = crack_times.get("offline_slow_hashing_1e4_per_second")

    feedback = result.get("feedback", {}) or {}
    warning = feedback.get("warning") or ""
    suggestions = feedback.get("suggestions") or []
    message = warning if warning else ""
    if suggestions:
        message = f"{message} {' '.join(suggestions)}".strip()

    return ZxcvbnResult(normalized_score, raw_score, guesses, crack_time_seconds, message or "zxcvbn analysis complete")
