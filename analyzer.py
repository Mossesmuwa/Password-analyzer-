#!/usr/bin/env python3
import math
import re
import argparse
from rich.console import Console
from rich.progress import track

console = Console()

# Load common passwords
def load_common_passwords(file_path="common_passwords.txt"):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return set([line.strip().lower() for line in f])
    except FileNotFoundError:
        console.print("[yellow][!] common_passwords.txt not found, using default list[/]")
        return {"password", "123456", "qwerty", "admin", "welcome", "letmein"}

COMMON_PASSWORDS = load_common_passwords()

SUBSTITUTIONS = {
    "@": "a",
    "$": "s",
    "0": "o",
    "1": "i",
    "3": "e",
    "7": "t"
}

def entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32  # approx special chars
    return len(password) * math.log2(charset) if charset else 0

def crack_time(entropy_bits: float, guesses_per_sec=1e9) -> str:
    seconds = 2**entropy_bits / guesses_per_sec
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"

def check_substitutions(password: str) -> str:
    decoded = "".join(SUBSTITUTIONS.get(ch, ch) for ch in password.lower())
    return decoded if decoded in COMMON_PASSWORDS else None

def analyze_password(password: str):
    report = []

    # Dictionary check
    if password.lower() in COMMON_PASSWORDS:
        report.append("[red]❌ Found in common passwords list[/]")

    # Substitution check
    sub_check = check_substitutions(password)
    if sub_check:
        report.append(f"[red]❌ Looks like a weak substitution of '{sub_check}'[/]")

    # Entropy & crack time
    e = entropy(password)
    t = crack_time(e)
    report.append(f"[cyan]🔑 Entropy:[/] {e:.2f} bits")
    report.append(f"[cyan]⏳ Estimated crack time:[/] {t}")

    # Final verdict
    if e < 40:
        verdict = "[red]VERY WEAK ❌[/]"
    elif e < 60:
        verdict = "[yellow]WEAK ⚠️[/]"
    elif e < 80:
        verdict = "[green]MEDIUM ✅[/]"
    else:
        verdict = "[bold green]STRONG 🔒[/]"
    report.append(f"[bold]Overall:[/] {verdict}")

    return "\n".join(report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔐 Password Strength Analyzer")
    parser.add_argument("-p", "--password", help="Password to analyze")
    args = parser.parse_args()

    if args.password:
        console.print(analyze_password(args.password))
    else:
        pwd = console.input("[bold cyan]Enter a password to analyze: [/]")
        console.print(analyze_password(pwd))
