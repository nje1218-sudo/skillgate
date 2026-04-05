#!/usr/bin/env python3
"""SkillGate — OSV Dependency Vulnerability Scanner.

Finds dependency manifests in a skill directory and queries the OSV.dev API
for known vulnerabilities. Also checks against the local malicious_packages
list in supply-chain-ioc.json.

Supported manifests:
  requirements.txt, requirements*.txt
  package.json
  pyproject.toml (tool.poetry.dependencies / project.dependencies)
  Pipfile

Usage:
  python3 check-dependencies.py <target_dir> [supply-chain-ioc.json]

Exit codes:
  0 = clean (no known vulnerabilities)
  1 = CRITICAL severity CVE found  OR  malicious package detected
  2 = HIGH or MEDIUM severity CVE found
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
TIMEOUT = 20
MAX_BATCH = 1000  # OSV batch limit

DEFAULT_IOC = (
    Path(__file__).parent.parent / "configs" / "supply-chain-ioc.json"
)
SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv"}


# ── Manifest Parsers ───────────────────────────────────────────────────────────

def parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Return list of (name, version_or_empty)."""
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http")):
            continue
        # Strip extras like [security], environment markers
        line = re.split(r";|\s", line)[0]
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]{1,3})\s*([^\s,]+)?", line)
        if m:
            name = m.group(1).lower()
            ver  = m.group(3) or ""
            pkgs.append((name, ver))
        else:
            # Bare name
            clean = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if clean:
                pkgs.append((clean.group(1).lower(), ""))
    return pkgs


def parse_package_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver_spec in data.get(section, {}).items():
            ver = re.sub(r"[^0-9.]", "", ver_spec.lstrip("^~>=<"))
            pkgs.append((name.lower(), ver))
    return pkgs


def parse_pyproject_toml(text: str) -> list[tuple[str, str]]:
    pkgs = []
    # [project] dependencies = ["pkg>=1.0", ...]
    m = re.search(r"\[project\].*?dependencies\s*=\s*\[(.*?)\]",
                  text, re.DOTALL | re.IGNORECASE)
    if m:
        for dep in re.findall(r'"([^"]+)"', m.group(1)):
            clean = re.match(r"([A-Za-z0-9_.\-]+)", dep)
            if clean:
                ver = re.search(r"[=<>]{1,2}([\d.]+)", dep)
                pkgs.append((clean.group(1).lower(), ver.group(1) if ver else ""))
    # [tool.poetry.dependencies]
    section_m = re.search(r"\[tool\.poetry\.dependencies\](.*?)(\[|\Z)",
                          text, re.DOTALL | re.IGNORECASE)
    if section_m:
        for line in section_m.group(1).splitlines():
            kv = re.match(r'\s*([A-Za-z0-9_.\-]+)\s*=\s*["\'^~>=<]*([0-9.]*)', line)
            if kv and kv.group(1).lower() not in ("python",):
                pkgs.append((kv.group(1).lower(), kv.group(2)))
    return pkgs


def parse_pipfile(text: str) -> list[tuple[str, str]]:
    pkgs = []
    in_packages = False
    for line in text.splitlines():
        if re.match(r"\[(packages|dev-packages)\]", line, re.IGNORECASE):
            in_packages = True
            continue
        if line.startswith("[") and in_packages:
            in_packages = False
        if not in_packages:
            continue
        kv = re.match(r'\s*([A-Za-z0-9_.\-]+)\s*=\s*["\'^~>=<*]*([0-9.]*)', line)
        if kv:
            pkgs.append((kv.group(1).lower(), kv.group(2)))
    return pkgs


def find_manifests(root: Path) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Return list of (ecosystem, file_path, [(name, version)])."""
    results = []
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        name = p.name.lower()
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue

        if re.match(r"requirements.*\.txt$", name):
            pkgs = parse_requirements_txt(text)
            if pkgs:
                results.append(("PyPI", str(p), pkgs))
        elif name == "package.json":
            pkgs = parse_package_json(text)
            if pkgs:
                results.append(("npm", str(p), pkgs))
        elif name == "pyproject.toml":
            pkgs = parse_pyproject_toml(text)
            if pkgs:
                results.append(("PyPI", str(p), pkgs))
        elif name == "pipfile":
            pkgs = parse_pipfile(text)
            if pkgs:
                results.append(("PyPI", str(p), pkgs))

    return results


# ── OSV Query ─────────────────────────────────────────────────────────────────

def query_osv(packages: list[tuple[str, str, str]]) -> list[dict]:
    """
    packages: list of (ecosystem, name, version)
    Returns flat list of OSV vuln objects that match.
    """
    if not packages:
        return []

    queries = []
    for eco, name, ver in packages[:MAX_BATCH]:
        q: dict = {"package": {"ecosystem": eco, "name": name}}
        if ver:
            q["version"] = ver
        queries.append(q)

    payload = {"queries": queries}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SkillGate-DepCheck/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            resp = json.loads(r.read().decode())
    except (urllib.error.URLError, OSError) as exc:
        print(f"  WARN: OSV query failed: {exc}", file=sys.stderr)
        return []

    vulns = []
    for result in resp.get("results", []):
        vulns.extend(result.get("vulns", []))
    return vulns


def max_severity(vuln: dict) -> str:
    """Return the highest CVSS severity string from a vuln object."""
    severities = []
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS v3 vector score e.g. "CVSS:3.1/AV:N/AC:L/..."
        m = re.search(r"CVSS:3\.\d/.*?/(.+)", score_str)
        if not m:
            continue
        base = sev.get("type", "CVSS_V3")
        # Fall back to database_specific CVSS score
        for db in vuln.get("database_specific", {}).values():
            if isinstance(db, dict):
                s = db.get("cvss_score", 0)
                if s >= 9.0:
                    severities.append("CRITICAL")
                elif s >= 7.0:
                    severities.append("HIGH")
                elif s >= 4.0:
                    severities.append("MEDIUM")
    # Also check severity field directly
    for sev in vuln.get("severity", []):
        t = sev.get("type", "")
        score = sev.get("score", "")
        if "CVSS" in t:
            # parse base score from vector
            bm = re.search(r"(\d+\.\d+)$", score)
            if bm:
                s = float(bm.group(1))
                if s >= 9.0:
                    severities.append("CRITICAL")
                elif s >= 7.0:
                    severities.append("HIGH")
                elif s >= 4.0:
                    severities.append("MEDIUM")
    # Check aliases for known critical patterns
    for alias in vuln.get("aliases", []):
        if alias.startswith("MAL-"):
            return "CRITICAL"  # Malicious package = critical
    return severities[0] if severities else "UNKNOWN"


# ── Malicious package check ────────────────────────────────────────────────────

def load_malicious_packages(ioc_path: Path) -> dict[str, set[str]]:
    """Return {'pypi': {name,...}, 'npm': {name,...}} from IOC JSON."""
    if not ioc_path.exists():
        return {}
    try:
        ioc = json.loads(ioc_path.read_text())
        mal = ioc.get("malicious_packages", {})
        return {eco: set(names) for eco, names in mal.items()}
    except Exception:
        return {}


ECO_MAP = {"PyPI": "pypi", "npm": "npm"}


def check_malicious_packages(
    manifests: list[tuple[str, str, list[tuple[str, str]]]],
    mal_pkgs: dict[str, set[str]],
) -> list[str]:
    hits = []
    for eco, fpath, pkgs in manifests:
        eco_key = ECO_MAP.get(eco, eco.lower())
        blocked = mal_pkgs.get(eco_key, set())
        for name, _ in pkgs:
            if name in blocked:
                hits.append(f"🔴 MALICIOUS PACKAGE [{eco}]: {name} in {fpath}")
    return hits


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check-dependencies.py <target_dir> [ioc.json]")
        return 1

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Not found: {target}")
        return 1

    ioc_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_IOC

    manifests = find_manifests(target)
    if not manifests:
        print("OK: no dependency manifests found")
        return 0

    total_pkgs = sum(len(p) for _, _, p in manifests)
    print(f"[dep-check] Found {len(manifests)} manifest(s), {total_pkgs} package(s)")

    # 1) Malicious package list check (local, fast)
    mal_pkgs = load_malicious_packages(ioc_path)
    mal_hits = check_malicious_packages(manifests, mal_pkgs)
    for h in mal_hits:
        print(h)

    # 2) OSV vulnerability check (network)
    all_packages: list[tuple[str, str, str]] = []
    for eco, _, pkgs in manifests:
        for name, ver in pkgs:
            all_packages.append((eco, name, ver))

    print(f"[dep-check] Querying OSV for {len(all_packages)} package(s)...")
    vulns = query_osv(all_packages)

    if not vulns and not mal_hits:
        print("OK: no known vulnerabilities detected")
        return 0

    critical_found = bool(mal_hits)
    high_found = False

    seen = set()
    for v in vulns:
        vid = v.get("id", "")
        if vid in seen:
            continue
        seen.add(vid)

        sev = max_severity(v)
        aliases = ", ".join(v.get("aliases", [])[:3])
        pkg_info = ""
        for aff in v.get("affected", []):
            pkg = aff.get("package", {})
            pkg_info = f"{pkg.get('ecosystem','')}/{pkg.get('name','')}"
            break
        summary = v.get("summary", "")[:80]
        label = f"[{sev}] {vid} ({aliases}) {pkg_info}: {summary}"

        if sev == "CRITICAL" or vid.startswith("MAL-"):
            print(f"🔴 CRITICAL: {label}")
            critical_found = True
        elif sev == "HIGH":
            print(f"🟠 HIGH: {label}")
            high_found = True
        elif sev in ("MEDIUM", "UNKNOWN") and not vid.startswith("MAL-"):
            print(f"🟡 {sev}: {label}")
            high_found = True

    if critical_found:
        return 1
    if high_found:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
