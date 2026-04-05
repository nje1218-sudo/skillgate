#!/usr/bin/env python3
"""SkillGate policy-as-code (lightweight stub).

Goal: provide a deterministic, greppable check that flags high-risk patterns in a skill repo.
This is NOT a full replacement for skill-vetting/SecureClaw; it's a guardrail.

Usage:
  python3 policy_check.py <path>

Exit codes:
  0 = ok
  1 = block-level violation (network_exec, decode_and_run, secrets_path_reference)
  2 = warn-level violation only (webhook, install_hooks)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# block level — matches policy.yaml rules: network_exec_keywords, decode_and_run, secrets_path_reference
BLOCK_PATTERNS = {
    "network_exec": re.compile(r"\b(curl|wget|nc|powershell)\b|bash\s+-c", re.I),
    "decode_and_run": re.compile(r"base64\s+(-d|--decode)|eval\s*\(|exec\s*\(|\.b64decode\b", re.I),
    "secrets_path_reference": re.compile(r"secrets/|\.ssh/", re.I),
}

# warn level — matches policy.yaml rules: webhook_or_url, install_hooks
# webhook_or_url: narrowed to execution contexts only (not bare URLs in docs/comments)
WARN_PATTERNS = {
    "webhook_or_url": re.compile(
        r'(fetch|axios|requests\.get|requests\.post|urllib)\s*\(\s*["\']https?://'
        r'|https?://[^\s"\']*webhook'
        r'|\bwebhook\b',
        re.I,
    ),
    "install_hooks": re.compile(r"postinstall|preinstall", re.I),
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

    block_violations: list[tuple[str, str]] = []
    warn_violations: list[tuple[str, str]] = []

    for f in iter_files(root):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue

        for key, rx in BLOCK_PATTERNS.items():
            if rx.search(text):
                block_violations.append((key, str(f)))

        for key, rx in WARN_PATTERNS.items():
            if rx.search(text):
                warn_violations.append((key, str(f)))

    if block_violations:
        print("BLOCK_VIOLATIONS:")
        for key, f in block_violations[:200]:
            print(f"- {key}: {f}")
        if len(block_violations) > 200:
            print(f"... and {len(block_violations)-200} more")

    if warn_violations:
        print("WARN_VIOLATIONS:")
        for key, f in warn_violations[:200]:
            print(f"- {key}: {f}")
        if len(warn_violations) > 200:
            print(f"... and {len(warn_violations)-200} more")

    if block_violations:
        return 1
    if warn_violations:
        return 2

    print("OK: no policy violations detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
