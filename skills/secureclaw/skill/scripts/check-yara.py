#!/usr/bin/env python3
"""SecureClaw — YARA Supply Chain Scanner.

Compiles and runs supply-chain.yar against a skill directory.
Gracefully skips if neither yara-python nor the yara CLI is available
(exit 2 / WARN) so it does not block pipelines in minimal environments.

Usage:
  python3 check-yara.py <target_dir> [rules.yar]

Exit codes:
  0 = clean (no YARA matches)
  1 = CRITICAL or HIGH severity match found (block)
  2 = MEDIUM match found OR yara unavailable (warn / skip)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

RULES_DEFAULT = (
    Path(__file__).parent.parent / "rules" / "supply-chain.yar"
)

# Map rule name prefixes → severity (fallback when meta unavailable)
_SEVERITY_HINTS = {
    "CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 2,
}

# Rule names whose hits are always CRITICAL regardless of meta
_ALWAYS_CRITICAL = {
    "sc_pipe_to_shell", "sc_env_exfiltration", "sc_openclaw_credential_access",
    "sc_aws_key_theft", "sc_ssh_key_access", "sc_crypto_wallet_hook",
    "sc_clawhavoc_c2", "sc_clawhavoc_patterns",
}


def _parse_yara_cli_output(text: str) -> list[tuple[str, str]]:
    """Parse `yara` CLI output lines: '<rule> <file>'"""
    hits = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            hits.append((parts[0], parts[1]))
    return hits


def run_with_yara_python(rules_path: Path, target: Path) -> tuple[int, str]:
    try:
        import yara  # type: ignore
    except ImportError:
        return 2, "# SKIP: yara-python not installed\n"

    try:
        compiled = yara.compile(filepath=str(rules_path))
    except Exception as e:
        return 2, f"# SKIP: YARA compile error: {e}\n"

    block_hits: list[str] = []
    warn_hits:  list[str] = []

    for p in target.rglob("*"):
        if not p.is_file():
            continue
        try:
            matches = compiled.match(str(p))
        except Exception:
            continue
        for m in matches:
            severity = (m.meta or {}).get("severity", "").upper()
            exit_code = _SEVERITY_HINTS.get(severity, 2)
            if m.rule in _ALWAYS_CRITICAL:
                exit_code = 1
            rel = str(p.relative_to(target) if p.is_relative_to(target) else p)
            entry = f"  [{severity or 'UNKNOWN'}] {m.rule}: {rel}"
            if exit_code == 1:
                block_hits.append(entry)
            else:
                warn_hits.append(entry)

    out = ""
    if block_hits:
        out += "🔴 [BLOCK — YARA MATCH]\n" + "\n".join(block_hits) + "\n"
    if warn_hits:
        out += "🟠 [WARN — YARA MATCH]\n" + "\n".join(warn_hits) + "\n"
    if not block_hits and not warn_hits:
        out = "OK: no YARA matches\n"

    return (1 if block_hits else (2 if warn_hits else 0)), out


def run_with_yara_cli(rules_path: Path, target: Path) -> tuple[int, str]:
    yara_bin = shutil.which("yara")
    if not yara_bin:
        return 2, "# SKIP: yara not available (install yara-python or yara CLI)\n"

    try:
        result = subprocess.run(
            [yara_bin, "-r", str(rules_path), str(target)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return 2, "# TIMEOUT: yara scan exceeded 30s\n"

    hits = _parse_yara_cli_output(result.stdout)
    if not hits:
        return 0, "OK: no YARA matches\n"

    block_hits: list[str] = []
    warn_hits:  list[str] = []

    # Load rule metadata from file to determine severity (CLI doesn't expose meta easily)
    yar_text = rules_path.read_text(errors="ignore")
    rule_severities: dict[str, int] = {}
    for m in re.finditer(r'rule\s+(\w+)[^{]*\{[^}]*severity\s*=\s*"([^"]+)"', yar_text, re.S):
        sev = m.group(2).upper()
        rule_severities[m.group(1)] = _SEVERITY_HINTS.get(sev, 2)

    for rule_name, filepath in hits:
        exit_code = rule_severities.get(rule_name, 2)
        if rule_name in _ALWAYS_CRITICAL:
            exit_code = 1
        sev_label = {1: "CRITICAL/HIGH", 2: "MEDIUM"}.get(exit_code, "UNKNOWN")
        entry = f"  [{sev_label}] {rule_name}: {filepath}"
        if exit_code == 1:
            block_hits.append(entry)
        else:
            warn_hits.append(entry)

    out = ""
    if block_hits:
        out += "🔴 [BLOCK — YARA MATCH]\n" + "\n".join(block_hits) + "\n"
    if warn_hits:
        out += "🟠 [WARN — YARA MATCH]\n" + "\n".join(warn_hits) + "\n"

    return (1 if block_hits else 2), out


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-yara.py <target_dir> [rules.yar]")
        return 1

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Not found: {target}")
        return 1

    rules_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else RULES_DEFAULT
    if not rules_path.exists():
        print(f"# SKIP: rules file not found: {rules_path}")
        return 2

    # Try yara-python first (richer metadata), then CLI
    try:
        import yara  # noqa: F401
        exit_code, output = run_with_yara_python(rules_path, target)
    except ImportError:
        exit_code, output = run_with_yara_cli(rules_path, target)

    print(output, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
