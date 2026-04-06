#!/usr/bin/env python3
"""SecureClaw — Supply Chain IOC Enforcer.

Reads supply-chain-ioc.json and checks a skill directory for:
  - Name matching known malicious skill name patterns
  - C2 server / malicious domain references in code
  - Infostealer target path references in code
  - Suspicious skill patterns (ClickFix, webhook.site, osascript, etc.)

Usage:
  python3 check-ioc.py <skill_dir> [skill_name] [supply-chain-ioc.json]

Exit codes:
  0 = clean
  1 = IOC match found (block)
  2 = suspicious pattern found (warn)
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from skillgate_utils import iter_files, SKIP_DIRS  # noqa: E402


def load_ioc(config_path: Path) -> dict:
    return json.loads(config_path.read_text())


def _normalize(s: str) -> str:
    """Normalize separators for typosquatting detection."""
    return re.sub(r'[-_.]', '', s).lower()


def check_name_patterns(skill_name: str, name_patterns: list[str]) -> list[str]:
    hits = []
    name_lower = skill_name.lower()
    name_norm = _normalize(skill_name)
    for pattern in name_patterns:
        if pattern.lower() in name_lower or _normalize(pattern) in name_norm:
            hits.append(pattern)
    return hits


def check_content(root: Path, patterns: list[re.Pattern]) -> list[tuple[str, str]]:
    """Return list of (pattern_str, file_path) for first hit per file per pattern."""
    hits = []
    for f in iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for rx in patterns:
            if rx.search(text):
                hits.append((rx.pattern, str(f)))
                break  # one hit per file is enough
    return hits


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-ioc.py <skill_dir> [skill_name] [ioc.json]")
        return 1

    skill_dir = Path(sys.argv[1]).resolve()
    if not skill_dir.exists():
        print(f"Not found: {skill_dir}")
        return 1

    skill_name = sys.argv[2] if len(sys.argv) >= 3 else skill_dir.name

    if len(sys.argv) >= 4:
        config_path = Path(sys.argv[3])
    else:
        config_path = Path(__file__).parent.parent / "configs" / "supply-chain-ioc.json"

    if not config_path.exists():
        print(f"IOC config not found: {config_path}")
        return 1

    ioc = load_ioc(config_path)
    clawhavoc = ioc.get("clawhavoc", {})

    block_findings: list[str] = []
    warn_findings: list[str] = []

    # 1) Skill name vs known malicious name patterns (block)
    name_hits = check_name_patterns(skill_name, clawhavoc.get("name_patterns", []))
    for hit in name_hits:
        block_findings.append(f"name matches ClawHavoc blocklist: '{hit}'")

    # 2) C2 servers and malicious domains in code (block)
    indicators = list(set(
        ioc.get("c2_servers", []) + ioc.get("malicious_domains", [])
    ))
    if indicators:
        c2_patterns = [re.compile(re.escape(ind), re.I) for ind in indicators]
        for _, fpath in check_content(skill_dir, c2_patterns):
            block_findings.append(f"C2/malicious domain reference in: {fpath}")

    # 3) Infostealer target paths in code (block)
    stealer_targets = ioc.get("infostealer_targets", [])
    if stealer_targets:
        stealer_patterns = [re.compile(re.escape(t), re.I) for t in stealer_targets]
        for _, fpath in check_content(skill_dir, stealer_patterns):
            block_findings.append(f"infostealer target path reference in: {fpath}")

    # 4) Suspicious skill patterns (warn — most already caught by dangerous-commands; flag extras)
    suspicious = ioc.get("suspicious_skill_patterns", [])
    if suspicious:
        sus_patterns = [re.compile(p, re.I | re.DOTALL) for p in suspicious]
        for pat, fpath in check_content(skill_dir, sus_patterns):
            warn_findings.append(f"suspicious pattern '{pat}' in: {fpath}")

    if not block_findings and not warn_findings:
        print("OK: no IOC matches detected")
        return 0

    if block_findings:
        print("🔴 [BLOCK — IOC MATCH]")
        for f in block_findings:
            print(f"  - {f}")

    if warn_findings:
        print("🟠 [WARN — SUSPICIOUS PATTERN]")
        for f in warn_findings:
            print(f"  - {f}")

    return 1 if block_findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
