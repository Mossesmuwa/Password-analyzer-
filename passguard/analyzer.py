#!/usr/bin/env python3
"""
PassGuard — Password Strength Analyzer
Core analysis engine: entropy, crack time, substitution detection, and verdict.
"""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SUBSTITUTIONS: dict[str, str] = {
    "@": "a",
    "$": "s",
    "0": "o",
    "1": "i",
    "3": "e",
    "7": "t",
    "!": "i",
    "5": "s",
}

DEFAULT_COMMON_PASSWORDS: set[str] = {
    "password", "123456", "qwerty", "admin", "welcome", "letmein",
    "monkey", "dragon", "sunshine", "password1",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PasswordReport:
    password: str
    entropy_bits: float
    charset_size: int
    crack_time_str: str
    is_common: bool
    substitution_of: Optional[str]
    checks: dict[str, bool]
    strength: str          # COMPROMISED | VERY WEAK | WEAK | MODERATE | STRONG | FORTRESS
    score: int             # 0–5

    @property
    def passed_checks(self) -> int:
        return sum(self.checks.values())

    @property
    def total_checks(self) -> int:
        return len(self.checks)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_common_passwords(path: str | Path = "common_passwords.txt") -> set[str]:
    """Load common passwords from a newline-separated file.

    Falls back to a minimal built-in list when the file is missing.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        return {line.strip().lower() for line in text.splitlines() if line.strip()}
    except FileNotFoundError:
        return DEFAULT_COMMON_PASSWORDS


COMMON_PASSWORDS: set[str] = load_common_passwords()


# ---------------------------------------------------------------------------
# Core calculations
# ---------------------------------------------------------------------------

def compute_entropy(password: str) -> tuple[float, int]:
    """Return (entropy_bits, charset_size) for *password*."""
    charset = 0
    if re.search(r"[a-z]", password):         charset += 26
    if re.search(r"[A-Z]", password):         charset += 26
    if re.search(r"[0-9]", password):         charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):  charset += 32
    bits = len(password) * math.log2(charset) if charset else 0.0
    return bits, charset


def format_crack_time(entropy_bits: float, guesses_per_sec: float = 1e9) -> str:
    """Human-readable estimated crack time at *guesses_per_sec* rate."""
    seconds = (2 ** entropy_bits) / guesses_per_sec
    thresholds = [
        (60,          lambda s: f"{s:.1f} seconds"),
        (3_600,       lambda s: f"{s / 60:.1f} minutes"),
        (86_400,      lambda s: f"{s / 3_600:.1f} hours"),
        (31_536_000,  lambda s: f"{s / 86_400:.1f} days"),
        (3.15e10,     lambda s: f"{s / 31_536_000:.0f} years"),
    ]
    for limit, fmt in thresholds:
        if seconds < limit:
            return fmt(seconds)
    return "centuries"


def detect_substitution(password: str, common: set[str] = COMMON_PASSWORDS) -> Optional[str]:
    """Return the base word if *password* is a leet-speak substitution of a common password."""
    decoded = "".join(SUBSTITUTIONS.get(ch, ch) for ch in password.lower())
    return decoded if decoded in common else None


def run_checks(password: str, common: set[str] = COMMON_PASSWORDS) -> dict[str, bool]:
    """Return a dict of security check name → pass/fail."""
    return {
        "min_length":       len(password) >= 8,
        "long_length":      len(password) >= 12,
        "has_uppercase":    bool(re.search(r"[A-Z]", password)),
        "has_lowercase":    bool(re.search(r"[a-z]", password)),
        "has_digit":        bool(re.search(r"[0-9]", password)),
        "has_special":      bool(re.search(r"[^a-zA-Z0-9]", password)),
        "not_common":       password.lower() not in common,
        "no_substitution":  detect_substitution(password, common) is None,
    }


def _score(entropy_bits: float, is_common: bool, has_sub: bool) -> tuple[int, str]:
    """Map entropy and flags to a (score 0-5, label) tuple."""
    if is_common or has_sub:
        return 0, "COMPROMISED"
    if entropy_bits < 30:
        return 1, "VERY WEAK"
    if entropy_bits < 50:
        return 2, "WEAK"
    if entropy_bits < 70:
        return 3, "MODERATE"
    if entropy_bits < 90:
        return 4, "STRONG"
    return 5, "FORTRESS"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(password: str, common: set[str] = COMMON_PASSWORDS) -> PasswordReport:
    """Analyze *password* and return a :class:`PasswordReport`."""
    entropy_bits, charset_size = compute_entropy(password)
    crack_time = format_crack_time(entropy_bits)
    is_common = password.lower() in common
    substitution_of = detect_substitution(password, common)
    checks = run_checks(password, common)
    score, strength = _score(entropy_bits, is_common, substitution_of is not None)

    return PasswordReport(
        password=password,
        entropy_bits=entropy_bits,
        charset_size=charset_size,
        crack_time_str=crack_time,
        is_common=is_common,
        substitution_of=substitution_of,
        checks=checks,
        strength=strength,
        score=score,
    )
