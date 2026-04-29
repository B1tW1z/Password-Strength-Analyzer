from __future__ import annotations

from dataclasses import dataclass
from math import log2


@dataclass(frozen=True)
class EntropyResult:
    score: float
    entropy_bits: float
    charset_size: int


def estimate(password: str, charset_size: int) -> EntropyResult:
    if not password or charset_size <= 1:
        return EntropyResult(0.0, 0.0, max(charset_size, 0))

    entropy_bits = len(password) * log2(charset_size)
    score = min(100.0, (entropy_bits / 80.0) * 100.0)
    return EntropyResult(score, entropy_bits, charset_size)
