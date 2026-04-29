from __future__ import annotations

from dataclasses import dataclass

try:
    from passwordmeter import test as _passwordmeter_test
except Exception:  # pragma: no cover
    _passwordmeter_test = None


@dataclass(frozen=True)
class RuleBasedResult:
    score: float
    raw_score: float
    feedback: str


def _fallback_score(password: str) -> RuleBasedResult:
    if not password:
        return RuleBasedResult(0.0, 0.0, "Empty password")

    length_score = min(len(password) * 5, 40)
    classes = [
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    ]
    class_score = sum(classes) * 15
    repeated_penalty = 10 if len(set(password)) <= max(2, len(password) // 2) else 0
    score = max(0.0, min(100.0, length_score + class_score - repeated_penalty))
    feedback = "Add more length and character variety"
    return RuleBasedResult(score, score / 100.0, feedback)


def _feedback_text(feedback) -> str:
    if isinstance(feedback, dict):
        values = [str(value).strip() for value in feedback.values() if value]
        return " ".join(values).strip() or "Rule-based analysis complete"

    if isinstance(feedback, (list, tuple, set)):
        values = [str(value).strip() for value in feedback if value]
        return " ".join(values).strip() or "Rule-based analysis complete"

    text = str(feedback).strip()
    return text or "Rule-based analysis complete"


def analyze(password: str) -> RuleBasedResult:
    if _passwordmeter_test is None:
        return _fallback_score(password)

    score, feedback = _passwordmeter_test(password)
    normalized = float(score)
    if normalized <= 1.0:
        normalized *= 100.0
    normalized = max(0.0, min(100.0, normalized))
    text = _feedback_text(feedback)
    return RuleBasedResult(normalized, float(score), text)
