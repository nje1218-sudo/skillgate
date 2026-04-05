#!/usr/bin/env python3
"""SecureClaw — Dangerous Commands Enforcer.

Reads dangerous-commands.json and scans a target directory for patterns.
Enforces action levels declared in the config (block / require_approval / warn).

Usage:
  python3 check-dangerous-commands.py <target_dir> [dangerous-commands.json]

Exit codes:
  0 = clean
  1 = block-level violation found
  2 = require_approval or warn only
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__"}

ACTION_EXIT = {"block": 1, "require_approval": 2, "warn": 2}
ACTION_ICON = {"block": "🔴", "require_approval": "🟠", "warn": "🟡"}


def iter_files(root: Path):
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.stat().st_size <= 2_000_000:
            yield p


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-dangerous-commands.py <target_dir> [config.json]")
        return 1

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Not found: {target}")
        return 1

    if len(sys.argv) >= 3:
        config_path = Path(sys.argv[2])
    else:
        config_path = Path(__file__).parent.parent / "configs" / "dangerous-commands.json"

    if not config_path.exists():
        print(f"Config not found: {config_path}")
        return 1

    categories = json.loads(config_path.read_text()).get("categories", {})

    compiled: dict[str, dict] = {}
    for cat, meta in categories.items():
        compiled[cat] = {
            "action": meta.get("action", "warn"),
            # re.DOTALL lets . match newlines — catches patterns split across lines
            "patterns": [re.compile(p, re.I | re.DOTALL) for p in meta.get("patterns", [])],
        }

    # (action, category, file_path)
    findings: list[tuple[str, str, str]] = []

    for f in iter_files(target):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for cat, meta in compiled.items():
            for rx in meta["patterns"]:
                if rx.search(text):
                    findings.append((meta["action"], cat, str(f)))
                    break  # one hit per category per file is enough

    if not findings:
        print("OK: no dangerous command patterns detected")
        return 0

    # Priority: block > require_approval > warn (don't use max() — block=1 < require_approval=2)
    worst_exit = 0
    has_block = any(a == "block" for a, _, _ in findings)
    for action in ("block", "require_approval", "warn"):
        hits = [(cat, fp) for a, cat, fp in findings if a == action]
        if not hits:
            continue
        icon = ACTION_ICON[action]
        print(f"{icon} [{action.upper()}]")
        for cat, fpath in hits:
            print(f"  - {cat}: {fpath}")

    if has_block:
        return 1
    return 2  # require_approval or warn


if __name__ == "__main__":
    raise SystemExit(main())
