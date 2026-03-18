"""
Tests for passguard.analyzer

Run with:  pytest
"""

import pytest
from passguard.analyzer import (
    analyze,
    compute_entropy,
    detect_substitution,
    format_crack_time,
    run_checks,
)

MOCK_COMMON = {"password", "123456", "qwerty", "admin", "letmein", "passw0rd"}


# ---------------------------------------------------------------------------
# compute_entropy
# ---------------------------------------------------------------------------

class TestComputeEntropy:
    def test_empty_password_returns_zero(self):
        bits, cs = compute_entropy("")
        assert bits == 0.0
        assert cs == 0

    def test_lowercase_only_charset(self):
        _, cs = compute_entropy("abcdef")
        assert cs == 26

    def test_mixed_charset(self):
        _, cs = compute_entropy("Abc1!")
        assert cs == 26 + 26 + 10 + 32

    def test_longer_password_has_higher_entropy(self):
        short, _ = compute_entropy("abc")
        long_, _ = compute_entropy("abcdefghij")
        assert long_ > short


# ---------------------------------------------------------------------------
# format_crack_time
# ---------------------------------------------------------------------------

class TestFormatCrackTime:
    def test_very_low_entropy_is_seconds(self):
        result = format_crack_time(1)
        assert "seconds" in result

    def test_medium_entropy_is_not_seconds(self):
        result = format_crack_time(60)
        assert "seconds" not in result

    def test_high_entropy_is_years_or_centuries(self):
        result = format_crack_time(200)
        assert "years" in result or "centuries" in result


# ---------------------------------------------------------------------------
# detect_substitution
# ---------------------------------------------------------------------------

class TestDetectSubstitution:
    def test_leet_speak_detected(self):
        # "p@ssw0rd" → "password"
        result = detect_substitution("p@ssw0rd", MOCK_COMMON)
        assert result == "password"

    def test_clean_password_not_detected(self):
        result = detect_substitution("CorrectHorseBatteryStaple!", MOCK_COMMON)
        assert result is None

    def test_case_insensitive(self):
        result = detect_substitution("P@SSWORD", MOCK_COMMON)
        assert result is not None


# ---------------------------------------------------------------------------
# run_checks
# ---------------------------------------------------------------------------

class TestRunChecks:
    def test_strong_password_passes_all(self):
        checks = run_checks("Tr0ub4dor&3_X!", MOCK_COMMON)
        assert all(checks.values())

    def test_common_password_fails_not_common(self):
        checks = run_checks("password", MOCK_COMMON)
        assert not checks["not_common"]

    def test_short_password_fails_length(self):
        checks = run_checks("ab1!", MOCK_COMMON)
        assert not checks["min_length"]

    def test_no_special_fails_special_check(self):
        checks = run_checks("Abcdef123", MOCK_COMMON)
        assert not checks["has_special"]


# ---------------------------------------------------------------------------
# analyze (integration)
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_common_password_is_compromised(self):
        report = analyze("password", MOCK_COMMON)
        assert report.strength == "COMPROMISED"
        assert report.score == 0

    def test_weak_password_low_score(self):
        report = analyze("abc", MOCK_COMMON)
        assert report.score <= 2

    def test_strong_password_high_score(self):
        report = analyze("Tr0ub4dor&3_X!99", MOCK_COMMON)
        assert report.score >= 4

    def test_report_fields_populated(self):
        report = analyze("Test1234!", MOCK_COMMON)
        assert report.entropy_bits > 0
        assert report.crack_time_str != ""
        assert isinstance(report.checks, dict)
        assert 0 <= report.score <= 5

    def test_leet_password_is_compromised(self):
        report = analyze("p@ssw0rd", MOCK_COMMON)
        assert report.strength == "COMPROMISED"
        assert report.substitution_of == "password"
