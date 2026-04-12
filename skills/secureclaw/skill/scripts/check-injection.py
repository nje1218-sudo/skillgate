#!/usr/bin/env python3
"""SecureClaw — Prompt Injection Detector.

Reads injection-patterns.json and scans a target directory for prompt
injection attempts embedded in skill code or data files.

Covers OWASP ASI01 (Goal Hijacking) attack patterns:
  identity_hijacking, action_directives, tool_output_poisoning,
  planning_manipulation, config_tampering, structural_hiding,
  social_engineering

Usage:
  python3 check-injection.py <target_dir> [injection-patterns.json]

Exit codes:
  0 = clean
  1 = high-confidence injection pattern found (block)
  2 = suspicious pattern found (warn)
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from skillgate_utils import iter_files, CODE_EXTS  # noqa: E402

# Categories that warrant a hard BLOCK (exit 1)
BLOCK_CATEGORIES = {
    "identity_hijacking",
    "action_directives",
    "config_tampering",
    "social_engineering",
}

# Icon per category type
CATEGORY_ICON = {
    "identity_hijacking":    "🔴",
    "action_directives":     "🔴",
    "config_tampering":      "🔴",
    "social_engineering":    "🔴",
    "tool_output_poisoning": "🟠",
    "planning_manipulation": "🟠",
    "structural_hiding":     "🟡",
}


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-injection.py <target_dir> [injection-patterns.json]")
        return 1

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Not found: {target}")
        return 1

    if len(sys.argv) >= 3:
        config_path = Path(sys.argv[2])
    else:
        config_path = Path(__file__).parent.parent / "configs" / "injection-patterns.json"

    if not config_path.exists():
        print(f"Config not found: {config_path}")
        return 1

    raw = json.loads(config_path.read_text())
    pattern_map: dict[str, list[str]] = raw.get("patterns", {})

    # Compile each category's patterns into a single alternation regex
    compiled: dict[str, re.Pattern] = {}
    for cat, phrases in pattern_map.items():
        if not phrases:
            continue
        alts = "|".join(re.escape(p) if not re.search(r'[.*+?^${}()|[\]\\]', p) else p
                        for p in phrases)
        compiled[cat] = re.compile(alts, re.I)

    # (category, file_path, matched_text)
    block_findings: list[tuple[str, str, str]] = []
    warn_findings:  list[tuple[str, str, str]] = []

    for f in iter_files(target):
        # Only scan code files — .md docs may legitimately contain example injection phrases
        if f.suffix.lower() not in CODE_EXTS:
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(f)
        for cat, rx in compiled.items():
            m = rx.search(text)
            if m:
                entry = (cat, rel, m.group(0)[:60])
                if cat in BLOCK_CATEGORIES:
                    block_findings.append(entry)
                else:
                    warn_findings.append(entry)
                break  # one hit per file is sufficient

    if not block_findings and not warn_findings:
        print("OK: no prompt injection patterns detected")
        return 0

    if block_findings:
        print("🔴 [BLOCK — INJECTION PATTERN]")
        for cat, fpath, snippet in block_findings:
            icon = CATEGORY_ICON.get(cat, "🔴")
            print(f"  {icon} {cat}: {fpath}")
            print(f"     snippet: {snippet!r}")

    if warn_findings:
        print("🟠 [WARN — SUSPICIOUS INJECTION INDICATOR]")
        for cat, fpath, snippet in warn_findings:
            icon = CATEGORY_ICON.get(cat, "🟠")
            print(f"  {icon} {cat}: {fpath}")
            print(f"     snippet: {snippet!r}")

    return 1 if block_findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
