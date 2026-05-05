"""
generator.py
------------
Generates a cryptographically strong suggested password that is guaranteed
to satisfy common composition rules (upper, lower, digit, symbol) and
reaches at least 16 characters.
"""

from __future__ import annotations

import secrets
import string

_UPPER   = string.ascii_uppercase
_LOWER   = string.ascii_lowercase
_DIGITS  = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

_ALL = _UPPER + _LOWER + _DIGITS + _SYMBOLS


def generate(length: int = 16) -> str:
    """Return a random password of *length* chars (minimum 16)."""
    length = max(length, 16)

    # Guarantee at least one character from each class
    mandatory = [
        secrets.choice(_UPPER),
        secrets.choice(_LOWER),
        secrets.choice(_DIGITS),
        secrets.choice(_SYMBOLS),
    ]

    rest = [secrets.choice(_ALL) for _ in range(length - len(mandatory))]
    pool = mandatory + rest

    # Fisher-Yates shuffle via secrets.SystemRandom for cryptographic quality
    rng = secrets.SystemRandom()
    rng.shuffle(pool)

    return "".join(pool)
