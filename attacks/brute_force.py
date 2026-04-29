from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from math import log2
from time import perf_counter
import string


CHARSETS = {
    "lowercase": string.ascii_lowercase,
    "alphanumeric": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + string.punctuation,
}


@dataclass(frozen=True)
class BruteForceResult:
    charset_name: str
    charset_size: int
    password_length: int
    combinations: int
    estimated_seconds: float
    actual_seconds: float | None
    attempts: int | None
    mode: str


def _estimated_seconds(charset_size: int, length: int, attempts_per_second: int) -> float:
    if charset_size <= 1 or length <= 0:
        return 0.0
    combinations = charset_size**length
    return combinations / 2 / attempts_per_second


def _should_attempt_actual(length: int, combinations: int) -> bool:
    return length <= 4 and combinations <= 500_000


def analyze(password: str, charset_name: str, attempts_per_second: int = 1_000_000) -> BruteForceResult:
    charset = CHARSETS.get(charset_name, CHARSETS["full"])
    charset_size = len(charset)
    length = len(password)
    combinations = charset_size**length if length else 1
    estimated_seconds = _estimated_seconds(charset_size, length, attempts_per_second)

    if not password:
        return BruteForceResult(charset_name, charset_size, 0, 1, 0.0, None, None, "estimated")

    if not _should_attempt_actual(length, combinations):
        return BruteForceResult(charset_name, charset_size, length, combinations, estimated_seconds, None, None, "estimated")

    start = perf_counter()
    attempts = 0
    target = password
    for candidate in product(charset, repeat=length):
        attempts += 1
        if "".join(candidate) == target:
            break
    actual_seconds = perf_counter() - start
    return BruteForceResult(charset_name, charset_size, length, combinations, estimated_seconds, actual_seconds, attempts, "actual")


def crack_time_for_length(length: int, charset_size: int, attempts_per_second: int = 1_000_000) -> float:
    if length <= 0 or charset_size <= 1:
        return 0.0
    return (charset_size**length) / 2 / attempts_per_second


def entropy_bits(password: str, charset_size: int) -> float:
    if not password or charset_size <= 1:
        return 0.0
    return len(password) * log2(charset_size)
