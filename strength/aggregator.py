from __future__ import annotations

from dataclasses import dataclass

from strength.entropy import EntropyResult
from strength.rule_based import RuleBasedResult
from strength.zxcvbn_adapter import ZxcvbnResult


@dataclass(frozen=True)
class AggregatedResult:
    zxcvbn_score: float
    rule_based_score: float
    entropy_score: float
    final_score: float
    rating: str
    entropy_bits: float
    charset_size: int


def _rating(score: float) -> str:
    if score < 40:
        return "Weak"
    if score < 70:
        return "Medium"
    return "Strong"


def aggregate(zxcvbn_result: ZxcvbnResult, rule_result: RuleBasedResult, entropy_result: EntropyResult) -> AggregatedResult:
    final_score = round(
        (zxcvbn_result.score * 0.5) + (rule_result.score * 0.3) + (entropy_result.score * 0.2),
        2,
    )
    return AggregatedResult(
        zxcvbn_score=round(zxcvbn_result.score, 2),
        rule_based_score=round(rule_result.score, 2),
        entropy_score=round(entropy_result.score, 2),
        final_score=final_score,
        rating=_rating(final_score),
        entropy_bits=round(entropy_result.entropy_bits, 2),
        charset_size=entropy_result.charset_size,
    )
