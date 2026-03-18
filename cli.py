#!/usr/bin/env python3
"""
PassGuard CLI — interactive and single-shot password analysis.

Usage
-----
    python -m passguard.cli                    # interactive prompt
    python -m passguard.cli -p "MyP@ss123!"   # single password
    python -m passguard.cli --batch file.txt   # analyze a file of passwords
"""

import argparse
import sys
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from passguard.analyzer import analyze, load_common_passwords, PasswordReport

console = Console()

# ---------------------------------------------------------------------------
# Visual helpers
# ---------------------------------------------------------------------------

STRENGTH_COLORS: dict[str, str] = {
    "COMPROMISED": "bold red",
    "VERY WEAK":   "red",
    "WEAK":        "dark_orange",
    "MODERATE":    "yellow",
    "STRONG":      "green",
    "FORTRESS":    "bold bright_green",
}

STRENGTH_BARS: dict[int, str] = {
    0: "[red]█[/red][dim]░░░░[/dim]",
    1: "[red]█[/red][dim]░░░░[/dim]",
    2: "[dark_orange]██[/dark_orange][dim]░░░[/dim]",
    3: "[yellow]███[/yellow][dim]░░[/dim]",
    4: "[green]████[/green][dim]░[/dim]",
    5: "[bold bright_green]█████[/bold bright_green]",
}

CHECK_LABELS: dict[str, str] = {
    "min_length":      "Minimum length  (≥ 8 chars)",
    "long_length":     "Recommended length (≥ 12 chars)",
    "has_uppercase":   "Uppercase letters  (A–Z)",
    "has_lowercase":   "Lowercase letters  (a–z)",
    "has_digit":       "Numbers  (0–9)",
    "has_special":     "Special characters  (!@#$ …)",
    "not_common":      "Not a common password",
    "no_substitution": "No weak substitution  (P@ss → pass)",
}


def _banner() -> Panel:
    title = Text("PassGuard", style="bold bright_white", justify="center")
    subtitle = Text("Password Strength Analyzer", style="dim", justify="center")
    content = Align.center(Text.assemble(title, "\n", subtitle))
    return Panel(content, border_style="bright_black", padding=(0, 4))


def _render_report(report: PasswordReport) -> None:
    color = STRENGTH_COLORS[report.strength]
    bar   = STRENGTH_BARS[report.score]

    # ── Header ──────────────────────────────────────────────────────────────
    console.print()
    console.rule(f"[{color}]{report.strength}  {bar}[/]", style="bright_black")

    # ── Warnings ────────────────────────────────────────────────────────────
    if report.is_common:
        console.print("  [bold red]✖  Found in common passwords list[/]")
    if report.substitution_of:
        console.print(
            f"  [bold red]✖  Leet-speak substitution of "
            f"[underline]{report.substitution_of}[/underline][/]"
        )

    # ── Metrics ─────────────────────────────────────────────────────────────
    metrics = Table.grid(padding=(0, 3))
    metrics.add_column(style="dim", min_width=18)
    metrics.add_column(style="bold bright_white")

    metrics.add_row("Entropy",      f"{report.entropy_bits:.1f} bits")
    metrics.add_row("Charset size", f"{report.charset_size} symbols")
    metrics.add_row("Length",       f"{len(report.password)} characters")
    metrics.add_row("Crack time",   report.crack_time_str)

    console.print(Panel(metrics, title="[dim]Metrics[/dim]", border_style="bright_black", padding=(0, 2)))

    # ── Security checks ─────────────────────────────────────────────────────
    checks_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=False, expand=True)
    checks_table.add_column(width=3)
    checks_table.add_column()

    for key, label in CHECK_LABELS.items():
        passed = report.checks.get(key, False)
        icon  = "[green]✔[/green]" if passed else "[dim]✖[/dim]"
        text  = label if passed else f"[dim]{label}[/dim]"
        checks_table.add_row(icon, text)

    console.print(
        Panel(
            checks_table,
            title=f"[dim]Checks  {report.passed_checks}/{report.total_checks}[/dim]",
            border_style="bright_black",
            padding=(0, 1),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def run_interactive(common_path: str) -> None:
    common = load_common_passwords(common_path)
    console.print(_banner())

    while True:
        try:
            password = console.input(
                "[bold cyan]  Password[/] [dim](or 'q' to quit):[/dim] "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if password.lower() in {"q", "quit", "exit"}:
            console.print("[dim]Goodbye.[/dim]")
            break

        if not password:
            continue

        _render_report(analyze(password, common))


def run_single(password: str, common_path: str) -> None:
    common = load_common_passwords(common_path)
    _render_report(analyze(password, common))


def run_batch(input_file: str, common_path: str) -> None:
    common = load_common_passwords(common_path)
    passwords = Path(input_file).read_text(encoding="utf-8", errors="ignore").splitlines()
    passwords = [p.strip() for p in passwords if p.strip()]

    console.print(_banner())
    console.print(f"  [dim]Analyzing {len(passwords)} passwords from [underline]{input_file}[/underline]…[/dim]\n")

    table = Table(box=box.ROUNDED, border_style="bright_black", show_lines=True, expand=True)
    table.add_column("Password",   style="bold", max_width=28, overflow="fold")
    table.add_column("Strength",   min_width=12)
    table.add_column("Entropy",    justify="right", min_width=8)
    table.add_column("Crack Time", min_width=12)
    table.add_column("Checks",     justify="center", min_width=7)

    for pwd in passwords:
        r = analyze(pwd, common)
        color = STRENGTH_COLORS[r.strength]
        table.add_row(
            pwd,
            f"[{color}]{r.strength}[/]",
            f"{r.entropy_bits:.1f} bits",
            r.crack_time_str,
            f"{r.passed_checks}/{r.total_checks}",
        )

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="PassGuard — Password Strength Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-p", "--password",
        metavar="PASSWORD",
        help="Analyze a single password",
    )
    parser.add_argument(
        "-b", "--batch",
        metavar="FILE",
        help="Analyze every password in FILE (one per line)",
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        default="common_passwords.txt",
        help="Path to common-passwords wordlist (default: common_passwords.txt)",
    )
    args = parser.parse_args()

    if args.password:
        run_single(args.password, args.wordlist)
    elif args.batch:
        run_batch(args.batch, args.wordlist)
    else:
        run_interactive(args.wordlist)


if __name__ == "__main__":
    main()
