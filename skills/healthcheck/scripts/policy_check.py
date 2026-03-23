#!/usr/bin/env python3
"""SkillGate policy-as-code (lightweight stub).

Goal: provide a deterministic, greppable check that flags high-risk patterns in a skill repo.
This is NOT a full replacement for skill-vetting/SecureClaw; it's a guardrail.

Usage:
  python3 policy_check.py <path>

Exit codes:
  0 = ok
  2 = policy violation found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS = {
    "network_exec": re.compile(r"\b(curl|wget|nc|powershell)\b|bash\s+-c", re.I),
    "decode_and_run": re.compile(r"base64\s+(-d|--decode)|decode\s*\(|eval\s*\(", re.I),
    "webhook": re.compile(r"https?://|webhook", re.I),
    "postinstall": re.compile(r"postinstall|preinstall", re.I),
}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__"}


def iter_files(root: Path):
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.stat().st_size <= 2_000_000:
            yield p


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: policy_check.py <path>")
        return 2

    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        print(f"Not found: {root}")
        return 2

    violations = []
    for f in iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue

        for key, rx in PATTERNS.items():
            if rx.search(text):
                violations.append((key, str(f)))

    if violations:
        print("POLICY_VIOLATIONS:")
        for key, f in violations[:200]:
            print(f"- {key}: {f}")
        if len(violations) > 200:
            print(f"... and {len(violations)-200} more")
        return 2

    print("OK: no policy violations detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
