# PassGuard 🔐

> A fast, accurate, and fully local password strength analyzer — with a beautiful terminal UI.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-orange?logo=pytest)](tests/)
[![Style: Ruff](https://img.shields.io/badge/style-ruff-black)](https://docs.astral.sh/ruff/)

PassGuard checks passwords against a configurable common-password wordlist, detects leet-speak substitutions, computes information-theoretic entropy, estimates crack time against a 1 B guess/sec attacker, and reports a clear **COMPROMISED → FORTRESS** verdict — all in your terminal with zero network calls.

---

## Features

|                               |                                                                     |
| ----------------------------- | ------------------------------------------------------------------- |
| **Entropy scoring**           | Shannon-entropy calculation over the actual character set used      |
| **Crack-time estimate**       | Assumes 1 billion guesses per second (GPU-class attack)             |
| **Common-password detection** | Ships with 100 + common passwords; drop in any wordlist             |
| **Substitution detection**    | Catches `P@ssw0rd`, `@dm1n`, etc. via configurable substitution map |
| **8 security checks**         | Length, case, digits, specials, not-common, no-substitution         |
| **Batch mode**                | Analyze a file of passwords and get a ranked table                  |
| **Clean API**                 | Import `analyze()` directly — no CLI required                       |
| **Rich terminal UI**          | Color-coded verdict, strength bar, metrics panel, check list        |

---

## Quick Start

### Install

```bash
# 1. Clone
git clone https://github.com/mossesmuwa/passguard.git
cd passguard

# 2. Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install
pip install -e .
```

### Run

```bash
# Interactive prompt
passguard

# Single password
passguard -p "MyP@ssword123!"

# Batch analysis
passguard --batch passwords.txt

# Use a custom wordlist
passguard --wordlist /path/to/rockyou.txt -p "hunter2"
```

---

## Usage

```
usage: passguard [-h] [-p PASSWORD] [-b FILE] [--wordlist FILE]

options:
  -p, --password PASSWORD   Analyze a single password
  -b, --batch FILE          Analyze every password in FILE (one per line)
  --wordlist FILE           Path to common-passwords wordlist
                            (default: common_passwords.txt)
```

### Example output

```
  STRONG  ████░
  ┌─ Metrics ──────────────────────┐
  │  Entropy       68.4 bits       │
  │  Charset size  94 symbols      │
  │  Length        12 characters   │
  │  Crack time    9340.2 years    │
  └────────────────────────────────┘
  ┌─ Checks 7/8 ───────────────────┐
  │  ✔  Minimum length  (≥ 8)      │
  │  ✖  Recommended length (≥ 12)  │
  │  ✔  Uppercase letters (A–Z)    │
  │  ✔  Lowercase letters (a–z)    │
  │  ✔  Numbers (0–9)              │
  │  ✔  Special characters         │
  │  ✔  Not a common password      │
  │  ✔  No weak substitution       │
  └────────────────────────────────┘
```

---

## Python API

PassGuard ships as an importable package — integrate it into your own tools:

```python
from passguard import analyze

report = analyze("Tr0ub4dor&3!")

print(report.strength)          # "STRONG"
print(report.score)             # 4  (0–5)
print(f"{report.entropy_bits:.1f} bits")
print(report.crack_time_str)    # "9340.2 years"
print(report.is_common)         # False
print(report.substitution_of)   # None
print(report.checks)            # {"min_length": True, "has_special": True, ...}
print(report.passed_checks)     # 8
```

### `PasswordReport` fields

| Field             | Type              | Description                            |
| ----------------- | ----------------- | -------------------------------------- |
| `password`        | `str`             | The analyzed password                  |
| `entropy_bits`    | `float`           | Information-theoretic entropy          |
| `charset_size`    | `int`             | Size of the character set used         |
| `crack_time_str`  | `str`             | Human-readable crack-time estimate     |
| `is_common`       | `bool`            | Found in the common-passwords wordlist |
| `substitution_of` | `str \| None`     | Base word if leet-speak detected       |
| `checks`          | `dict[str, bool]` | Individual security check results      |
| `strength`        | `str`             | Verdict label                          |
| `score`           | `int`             | 0 (COMPROMISED) to 5 (FORTRESS)        |

---

## Strength Scale

| Score | Label           | Entropy range                        |
| ----- | --------------- | ------------------------------------ |
| 0     | **COMPROMISED** | Common password or leet substitution |
| 1     | **VERY WEAK**   | < 30 bits                            |
| 2     | **WEAK**        | 30–49 bits                           |
| 3     | **MODERATE**    | 50–69 bits                           |
| 4     | **STRONG**      | 70–89 bits                           |
| 5     | **FORTRESS**    | ≥ 90 bits                            |

> Crack time assumes a GPU-class attacker at **1 billion guesses per second**.

---

## Project Structure

```
passguard/
├── passguard/
│   ├── __init__.py        # Public API
│   ├── __main__.py        # python -m passguard
│   ├── analyzer.py        # Core logic (entropy, checks, report)
│   └── cli.py             # Rich terminal interface
├── tests/
│   └── test_analyzer.py   # pytest test suite
├── common_passwords.txt   # Default wordlist
├── pyproject.toml         # Package metadata + tool config
└── README.md
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=passguard --cov-report=term-missing

# Lint & format
ruff check .
ruff format .

# Type check
mypy passguard/
```

---

## Bring Your Own Wordlist

PassGuard works with any newline-separated password list:

```bash
# Use RockYou (after decompressing)
passguard --wordlist rockyou.txt -p "hunter2"

# Use SecLists top-10k
passguard --wordlist top-10000-passwords.txt --batch candidates.txt
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [Rich](https://github.com/Textualize/rich) — beautiful terminal output
- Entropy model based on the character-set size approach from NIST SP 800-63B
