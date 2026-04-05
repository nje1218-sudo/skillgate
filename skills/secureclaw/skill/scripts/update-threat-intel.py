#!/usr/bin/env python3
"""SkillGate — Threat Intelligence Auto-Updater.

Fetches latest threat intelligence from public feeds and updates
supply-chain-ioc.json in-place.

Sources:
  - Feodo Tracker (abuse.ch)  : C2 IP blocklist
  - URLhaus     (abuse.ch)    : malicious URL / domain feed
  - OSSF Malicious Packages   : known malicious PyPI / npm packages

Usage:
  python3 update-threat-intel.py [--dry-run] [ioc.json]

Exit:
  0 = success (updated or already current)
  1 = fetch error (network / parse)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Feed URLs ──────────────────────────────────────────────────────────────────

FEODO_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
)
URLHAUS_URL = (
    "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"
)
# GitHub API — list files recently added/changed in OSSF malicious packages
OSSF_PYPI_API = (
    "https://api.github.com/repos/ossf/malicious-packages"
    "/contents/osv/malicious/pypi?per_page=100"
)
OSSF_NPM_API = (
    "https://api.github.com/repos/ossf/malicious-packages"
    "/contents/osv/malicious/npm?per_page=100"
)
OSSF_RAW = "https://raw.githubusercontent.com/ossf/malicious-packages/main/{path}"

DEFAULT_CONFIG = (
    Path(__file__).parent.parent / "configs" / "supply-chain-ioc.json"
)

TIMEOUT = 15  # seconds


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get(url: str, json_response: bool = False):
    """Simple HTTP GET, returns text or parsed JSON."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SkillGate-ThreatIntel/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read().decode("utf-8", errors="replace")
            return json.loads(body) if json_response else body
    except (urllib.error.URLError, OSError) as exc:
        print(f"  WARN: fetch failed for {url}: {exc}", file=sys.stderr)
        return None


def _post_json(url: str, payload: dict):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SkillGate-ThreatIntel/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError) as exc:
        print(f"  WARN: POST failed for {url}: {exc}", file=sys.stderr)
        return None


def dedup_sorted(lst: list[str]) -> list[str]:
    return sorted(set(lst))


# ── Feodo Tracker: C2 IPs ──────────────────────────────────────────────────────

def fetch_feodo_ips() -> list[str]:
    """Return list of C2 IPs from Feodo Tracker blocklist."""
    body = _get(FEODO_URL)
    if not body:
        return []
    ips = []
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # Each non-comment line is a plain IP
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                ips.append(line)
    print(f"  Feodo Tracker: {len(ips)} C2 IPs fetched")
    return ips


# ── URLhaus: malicious domains ─────────────────────────────────────────────────

def fetch_urlhaus_domains() -> list[str]:
    """Return high-confidence malicious domains from URLhaus."""
    data = _get(URLHAUS_URL, json_response=True)
    if not data or not isinstance(data.get("urls"), list):
        return []
    domains = []
    for entry in data["urls"]:
        # Only 'online' or recently active URLs
        if entry.get("url_status") not in ("online", "unknown"):
            continue
        url = entry.get("url", "")
        # Extract hostname
        m = re.match(r"https?://([^/:?#\s]+)", url)
        if m:
            host = m.group(1)
            # Skip IPs (handled by Feodo) and common CDNs
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                domains.append(host.lower())
    # Only keep domains appearing in multiple entries (reduce noise)
    from collections import Counter
    counts = Counter(domains)
    high_conf = [d for d, c in counts.items() if c >= 2]
    print(f"  URLhaus: {len(high_conf)} high-confidence malicious domains")
    return high_conf


# ── OSSF Malicious Packages ────────────────────────────────────────────────────

def _fetch_ossf_package_names(api_url: str, ecosystem: str) -> list[str]:
    """List files in OSSF malicious packages repo and extract package names."""
    entries = _get(api_url, json_response=True)
    if not entries or not isinstance(entries, list):
        return []

    names = []
    # Sample first 50 files to avoid rate-limiting
    for entry in entries[:50]:
        path = entry.get("path", "")
        if not path.endswith(".json"):
            continue
        raw_url = OSSF_RAW.format(path=path)
        osv = _get(raw_url, json_response=True)
        if not osv:
            continue
        # Extract affected package names
        for affected in osv.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem", "").lower() == ecosystem.lower():
                name = pkg.get("name", "").strip()
                if name:
                    names.append(name.lower())

    print(f"  OSSF {ecosystem}: {len(names)} malicious package names fetched")
    return names


def fetch_ossf_packages() -> dict[str, list[str]]:
    """Return {'pypi': [...], 'npm': [...]} malicious package names."""
    return {
        "pypi": _fetch_ossf_package_names(OSSF_PYPI_API, "PyPI"),
        "npm":  _fetch_ossf_package_names(OSSF_NPM_API, "npm"),
    }


# ── Merge into IOC JSON ────────────────────────────────────────────────────────

def update_ioc(ioc: dict, feodo_ips: list[str], urlhaus_domains: list[str],
               ossf_pkgs: dict[str, list[str]]) -> tuple[dict, int]:
    """Merge new intel into IOC dict. Returns (updated_dict, change_count)."""
    changes = 0

    # C2 servers (block)
    old_c2 = set(ioc.get("c2_servers", []))
    new_c2 = old_c2 | set(feodo_ips)
    if new_c2 != old_c2:
        ioc["c2_servers"] = dedup_sorted(list(new_c2))
        changes += len(new_c2 - old_c2)
        print(f"  +{len(new_c2 - old_c2)} new C2 IPs added")

    # Malicious domains
    old_domains = set(ioc.get("malicious_domains", []))
    new_domains = old_domains | set(urlhaus_domains)
    if new_domains != old_domains:
        ioc["malicious_domains"] = dedup_sorted(list(new_domains))
        changes += len(new_domains - old_domains)
        print(f"  +{len(new_domains - old_domains)} new malicious domains added")

    # Malicious packages (new top-level section)
    mal_pkgs = ioc.get("malicious_packages", {"pypi": [], "npm": []})
    for eco, names in ossf_pkgs.items():
        old_set = set(mal_pkgs.get(eco, []))
        new_set = old_set | set(names)
        if new_set != old_set:
            mal_pkgs[eco] = dedup_sorted(list(new_set))
            added = len(new_set - old_set)
            changes += added
            print(f"  +{added} new malicious {eco} packages added")
    ioc["malicious_packages"] = mal_pkgs

    if changes:
        ioc["lastUpdated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        # Bump patch version
        ver = ioc.get("version", "2.0.0")
        parts = ver.split(".")
        if len(parts) == 3:
            parts[2] = str(int(parts[2]) + 1)
            ioc["version"] = ".".join(parts)

    return ioc, changes


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", nargs="?", default=str(DEFAULT_CONFIG))
    ap.add_argument("--dry-run", action="store_true",
                    help="Print changes without writing")
    args = ap.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    ioc = json.loads(config_path.read_text())
    print("[update-threat-intel] Fetching feeds...")

    feodo_ips     = fetch_feodo_ips()
    urlhaus_doms  = fetch_urlhaus_domains()
    ossf_pkgs     = fetch_ossf_packages()

    ioc, total_changes = update_ioc(ioc, feodo_ips, urlhaus_doms, ossf_pkgs)

    if total_changes == 0:
        print("[update-threat-intel] No new indicators — IOC already current.")
        return 0

    print(f"[update-threat-intel] Total: {total_changes} new indicators")

    if args.dry_run:
        print("[update-threat-intel] --dry-run: skipping write")
        return 0

    config_path.write_text(json.dumps(ioc, indent=2, ensure_ascii=False) + "\n")
    print(f"[update-threat-intel] Updated: {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
