from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter


@dataclass(frozen=True)
class DictionaryResult:
    matched: bool
    matched_word: str | None
    match_type: str
    attempts: int
    elapsed_seconds: float


def simulate(password: str, wordlist: list[str], case_variations: bool = True) -> DictionaryResult:
    start = perf_counter()
    attempts = 0
    target = password.strip()
    normalized_target = target.casefold()

    for raw_word in wordlist:
        word = raw_word.strip()
        if not word:
            continue

        attempts += 1
        if word == target:
            return DictionaryResult(True, word, "exact", attempts, perf_counter() - start)

        if case_variations and word.casefold() == normalized_target:
            return DictionaryResult(True, word, "case-variation", attempts, perf_counter() - start)

    return DictionaryResult(False, None, "none", attempts, perf_counter() - start)
