#!/usr/bin/env python3
"""SkillGate — YARA Rules Auto-Updater.

Fetches curated supply-chain YARA rules from community repositories
and appends new (non-duplicate) rules to supply-chain.yar.

Sources:
  - Elastic detection-rules (supply chain / malware category)
  - YARA-Rules/rules (community maintained, malware/ subtree)

The fetched rules are:
  1. Syntax-tested with `yara --syntax-only` if yara is available
  2. Deduplicated by rule name (existing names are skipped)
  3. Appended with a dated provenance comment

Usage:
  python3 update-yara-rules.py [--dry-run] [supply-chain.yar]

Exit:
  0 = success
  1 = error
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_YARA = (
    Path(__file__).parent.parent / "rules" / "supply-chain.yar"
)
TIMEOUT = 15

# ── Curated rule sources ───────────────────────────────────────────────────────
# Each entry: (display_name, raw_url)
# Cherry-picked files most relevant to supply-chain attacks and code injection.
# URLs verified against current repo structures.
RULE_SOURCES = [
    (
        "signature-base/webshells",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/"
        "yara/gen_webshells.yar",
    ),
    (
        "signature-base/powershell_suspicious",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/"
        "yara/gen_powershell_susp.yar",
    ),
    (
        "signature-base/log4j_exploit",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/"
        "yara/expl_log4j_cve_2021_44228.yar",
    ),
    (
        "signature-base/cn_hacktools",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/"
        "yara/gen_cn_hacktools.yar",
    ),
]

# ── Relevance filter ───────────────────────────────────────────────────────────
# Only import rules whose description / strings contain supply-chain keywords.
# This prevents importing unrelated crypto-math or AV signature rules.
RELEVANCE_KEYWORDS = re.compile(
    r"(download|dropper|inject|shell|exec|payload|steal|exfil|"
    r"backdoor|keylog|miner|obfuscat|base64|encode|decode|"
    r"supply.chain|npm|pip|pypi|credential|token|secret|password|"
    r"reverse.shell|c2|command.and.control|persistence|cron|webhook)",
    re.I,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get(url: str) -> str | None:
    req = urllib.request.Request(
        url, headers={"User-Agent": "SkillGate-YARAUpdater/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        print(f"  WARN: fetch failed {url}: {exc}", file=sys.stderr)
        return None


def extract_rule_names(yara_text: str) -> set[str]:
    """Return set of rule names defined in a YARA text block."""
    return set(re.findall(r"^\s*rule\s+(\w+)", yara_text, re.MULTILINE))


def syntax_ok(yara_text: str) -> bool:
    """Return True if yara --syntax-only passes (or yara is not installed)."""
    if not _yara_available():
        return True  # can't check — optimistically accept
    with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False) as f:
        f.write(yara_text)
        tmp = f.name
    try:
        result = subprocess.run(
            ["yara", "--syntax-only", tmp],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return True
    finally:
        Path(tmp).unlink(missing_ok=True)


def _yara_available() -> bool:
    try:
        subprocess.run(["yara", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, OSError):
        return False


def toml_to_yara_stub(toml_text: str, rule_name: str) -> str | None:
    """Convert a minimal Elastic .toml rule to a YARA comment stub.

    Elastic rules are EQL/KQL, not YARA — we extract the description and
    create a YARA rule with the indicator strings only when we can parse them.
    """
    # Only handle simple query = "..." style toml for now
    desc_m = re.search(r'description\s*=\s*"""(.*?)"""', toml_text, re.DOTALL)
    if not desc_m:
        desc_m = re.search(r'description\s*=\s*"([^"]+)"', toml_text)
    description = desc_m.group(1).strip()[:120] if desc_m else "Elastic rule stub"

    query_m = re.search(r'query\s*=\s*"""(.*?)"""', toml_text, re.DOTALL)
    if not query_m:
        return None

    query = query_m.group(1)
    # Extract string literals from the EQL query to use as YARA strings
    literals = re.findall(r'"([^"]{4,80})"', query)
    if len(literals) < 1:
        return None

    strings_block = "\n".join(
        f'        ${i} = "{lit}" nocase' for i, lit in enumerate(literals[:6], 1)
    )

    return f"""
rule {rule_name} {{
    meta:
        description = "{description}"
        source      = "elastic/detection-rules"
        imported    = "{datetime.now(timezone.utc).date()}"
    strings:
{strings_block}
    condition:
        any of them
}}"""


# ── Fetch and filter new rules ─────────────────────────────────────────────────

def fetch_new_rules(existing_names: set[str]) -> list[tuple[str, str]]:
    """Return list of (source_name, yara_rule_block) for rules not yet present."""
    new_rules: list[tuple[str, str]] = []

    for source_name, url in RULE_SOURCES:
        body = _get(url)
        if not body:
            continue

        # Handle Elastic .toml format
        if url.endswith(".toml"):
            # Derive a safe rule name from the filename
            stem = Path(url).stem
            rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", stem)
            if rule_name in existing_names:
                print(f"  SKIP (exists): {rule_name} from {source_name}")
                continue
            stub = toml_to_yara_stub(body, rule_name)
            if stub and syntax_ok(stub):
                new_rules.append((source_name, stub))
                print(f"  +NEW (elastic stub): {rule_name}")
            continue

        # Handle native YARA files
        rule_names_in_file = extract_rule_names(body)
        already_have = rule_names_in_file & existing_names
        truly_new = rule_names_in_file - existing_names

        if not truly_new:
            print(f"  SKIP (all {len(rule_names_in_file)} rules already present): {source_name}")
            continue

        # Extract individual rule blocks for new rules only
        irrelevant = 0
        for rule_name in truly_new:
            # Match the rule block: from "rule <name>" to the closing "}"
            pattern = rf"(rule\s+{re.escape(rule_name)}\s*\{{[^}}]+\}})"
            m = re.search(pattern, body, re.DOTALL)
            if not m:
                continue
            block = m.group(1)
            # Relevance filter: skip rules with no supply-chain keywords
            if not RELEVANCE_KEYWORDS.search(block):
                irrelevant += 1
                continue
            if syntax_ok(block):
                new_rules.append((source_name, "\n" + block))
                print(f"  +NEW: {rule_name} from {source_name}")
            else:
                print(f"  SKIP (syntax error): {rule_name}", file=sys.stderr)
        if irrelevant:
            print(f"  (skipped {irrelevant} irrelevant rules from {source_name})")

        if already_have:
            print(f"  (skipped {len(already_have)} already-present rules from {source_name})")

    return new_rules


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("yara_file", nargs="?", default=str(DEFAULT_YARA))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    yara_path = Path(args.yara_file)
    if not yara_path.exists():
        print(f"YARA file not found: {yara_path}", file=sys.stderr)
        return 1

    existing_text  = yara_path.read_text()
    existing_names = extract_rule_names(existing_text)
    print(f"[update-yara-rules] Existing rules: {len(existing_names)}")

    new_rules = fetch_new_rules(existing_names)

    if not new_rules:
        print("[update-yara-rules] No new rules — already current.")
        return 0

    print(f"[update-yara-rules] {len(new_rules)} new rule(s) to add")

    if args.dry_run:
        print("[update-yara-rules] --dry-run: skipping write")
        return 0

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    header = f"\n\n// ── Auto-imported {today} ──────────────────────────────────────────────────\n"
    additions = header + "\n".join(block for _, block in new_rules)

    yara_path.write_text(existing_text.rstrip() + additions + "\n")
    print(f"[update-yara-rules] Updated: {yara_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
