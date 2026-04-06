#!/usr/bin/env python3
"""SkillGate — Report Generator (MVP).

Reads scan results from a completed intake out_dir and generates:
  - PERMISSIONS.md  : what the skill is allowed/denied to do
  - report.md       : human-readable risk summary
  - report.json     : machine-readable full report

Does NOT re-run any scanner. It is a pure output layer over existing results.

Usage:
  python3 generate_report.py <skill_name> <version> <out_dir>
                             [--policy policy.yaml]
                             [--profile balanced|strict]
                             [--reports-dir ./reports]

Exit:
  0 = report generated
  1 = error (missing inputs)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

DEFAULT_POLICY = Path(__file__).parent.parent / "configs" / "policy.yaml"

# ── Severity constants ────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

SEVERITY_ICON = {
    CRITICAL: "🔴",
    HIGH:     "🟠",
    MEDIUM:   "🟡",
    LOW:      "🔵",
    INFO:     "ℹ️",
}

# ── Policy loader ─────────────────────────────────────────────────────────────

def load_policy(policy_path: Path, profile: str) -> dict:
    """Return the profile dict from policy.yaml, or a sensible default."""
    default_balanced = {
        "network":             {"allow": True,  "block_if_undeclared": False},
        "sensitive_paths":     {"block": ["/.ssh/", "/etc/passwd", "secrets/", ".env"],
                                "warn":  ["/tmp/", "/var/log/"]},
        "command_execution":   {"allow": True,  "require_approval": ["os.system", "shell=True"]},
        "destructive_ops":     {"allow": False},
        "privilege_escalation":{"allow": False},
        "block_on_critical":   True,
        "block_on_high":       False,
        "warn_on_medium":      True,
        "warn_on_low":         False,
    }

    if not policy_path.exists():
        print(f"  WARN: policy file not found ({policy_path}), using built-in balanced defaults",
              file=sys.stderr)
        return default_balanced

    if not _YAML_OK:
        print("  WARN: pyyaml not installed, using built-in balanced defaults", file=sys.stderr)
        return default_balanced

    with open(policy_path) as f:
        data = yaml.safe_load(f)

    profiles = data.get("profiles", {})
    if profile not in profiles:
        print(f"  WARN: profile '{profile}' not in policy file, falling back to balanced",
              file=sys.stderr)
        profile = "balanced"

    return profiles.get(profile, default_balanced)


# ── Findings parser ───────────────────────────────────────────────────────────

class Finding:
    __slots__ = ("severity", "category", "detail", "file_path")

    def __init__(self, severity: str, category: str, detail: str, file_path: str = ""):
        self.severity  = severity
        self.category  = category
        self.detail    = detail
        self.file_path = file_path

    def to_dict(self) -> dict:
        return {
            "severity":  self.severity,
            "category":  self.category,
            "detail":    self.detail,
            "file_path": self.file_path,
        }


def parse_l1_findings(l1_path: Path) -> list[Finding]:
    """Extract structured findings from l1_findings.md."""
    if not l1_path.exists():
        return []

    text = l1_path.read_text(errors="ignore")
    findings: list[Finding] = []

    # ── policy_check.py output ──────────────────────────────────────────────
    # "BLOCK_VIOLATIONS:\n- network_exec: /path\n- ..."
    in_block = False
    in_warn  = False
    for line in text.splitlines():
        if "BLOCK_VIOLATIONS:" in line:
            in_block, in_warn = True, False
            continue
        if "WARN_VIOLATIONS:" in line:
            in_block, in_warn = False, True
            continue
        if line.startswith("##") or line.strip() == "":
            in_block = in_warn = False
            continue

        if (in_block or in_warn) and line.strip().startswith("-"):
            m = re.match(r"\s*-\s+(\w+):\s*(.+)", line)
            if m:
                cat  = m.group(1).strip()
                path = m.group(2).strip()
                sev  = CRITICAL if in_block else MEDIUM
                findings.append(Finding(sev, _policy_cat(cat), f"policy:{cat}", path))

    # ── check-dangerous-commands.py output ─────────────────────────────────
    # "🔴 [BLOCK]\n  - remote_code_execution: /path"
    # "🟠 [REQUIRE_APPROVAL]\n  - destructive: /path"
    block_section = re.compile(r"🔴 \[BLOCK\]")
    warn_section  = re.compile(r"🟠 \[REQUIRE_APPROVAL\]|🟡 \[WARN\]")
    lines = text.splitlines()
    current_sev = None
    for line in lines:
        if block_section.search(line):
            current_sev = CRITICAL
        elif warn_section.search(line):
            current_sev = HIGH
        elif current_sev and re.match(r"\s{2,}-\s+\w+:", line):
            m = re.match(r"\s+-\s+(\w+):\s*(.*)", line)
            if m:
                cat  = m.group(1).strip()
                path = m.group(2).strip()
                findings.append(Finding(current_sev, _cmd_cat(cat), f"cmd:{cat}", path))
        elif line.strip() == "" or line.startswith("##"):
            current_sev = None

    # ── check-ioc.py output ─────────────────────────────────────────────────
    # "🔴 [BLOCK — IOC MATCH]\n  - C2/malicious domain reference in: /path"
    ioc_section = False
    for line in lines:
        if "BLOCK — IOC MATCH" in line:
            ioc_section = True
        elif ioc_section and re.match(r"\s{2,}-\s+", line):
            detail = line.strip().lstrip("- ")
            m = re.match(r"(.+) in:\s*(.+)", detail)
            if m:
                findings.append(Finding(CRITICAL, "ioc", m.group(1).strip(), m.group(2).strip()))
            else:
                findings.append(Finding(CRITICAL, "ioc", detail))
        elif line.strip() == "" or (line.startswith("##") and ioc_section):
            ioc_section = False

    # ── Symlink escape ──────────────────────────────────────────────────────
    for line in lines:
        if "SYMLINK ESCAPE:" in line:
            m = re.search(r"SYMLINK ESCAPE:\s*(.+)\s*->\s*(.+)", line)
            if m:
                findings.append(Finding(CRITICAL, "symlink_escape",
                                        f"symlink {m.group(1).strip()} → {m.group(2).strip()}"))

    # ── Dep check ───────────────────────────────────────────────────────────
    for line in lines:
        if "MALICIOUS PACKAGE" in line:
            m = re.search(r"MALICIOUS PACKAGE \[(\w+)\]: (\S+) in (.+)", line)
            if m:
                findings.append(Finding(CRITICAL, "malicious_package",
                                        f"{m.group(1)}/{m.group(2)}", m.group(3)))
        elif line.startswith("🔴 CRITICAL:") and "CVE" in line:
            findings.append(Finding(CRITICAL, "cve", line[len("🔴 CRITICAL:"):].strip()))
        elif line.startswith("🟠 HIGH:") and "CVE" in line:
            findings.append(Finding(HIGH, "cve", line[len("🟠 HIGH:"):].strip()))

    return findings


def _policy_cat(key: str) -> str:
    mapping = {
        "network_exec":           "network",
        "decode_and_run":         "code_exec",
        "secrets_path_reference": "secrets",
        "webhook_or_url":         "network",
        "install_hooks":          "install_hook",
    }
    return mapping.get(key, key)


def _cmd_cat(key: str) -> str:
    mapping = {
        "remote_code_execution": "network",
        "dynamic_execution":     "code_exec",
        "data_exfiltration":     "data_exfil",
        "destructive":           "destructive",
        "permission_escalation": "privilege",
        "config_modification":   "persistence",
        "deserialization":       "code_exec",
    }
    return mapping.get(key, key)


def parse_semgrep(semgrep_path: Path) -> list[Finding]:
    if not semgrep_path.exists():
        return []
    try:
        data = json.loads(semgrep_path.read_text())
    except Exception:
        return []

    findings = []
    for r in data.get("results", []):
        sev_raw = r.get("extra", {}).get("severity", "INFO").upper()
        sev = CRITICAL if sev_raw == "ERROR" else HIGH if sev_raw == "WARNING" else MEDIUM
        rule  = r.get("check_id", "")
        path  = r.get("path", "")
        msg   = r.get("extra", {}).get("message", "")[:120]
        findings.append(Finding(sev, "semgrep", f"{rule}: {msg}", path))
    return findings


def parse_l2_report(l2_path: Path) -> list[Finding]:
    if not l2_path.exists():
        return []
    try:
        data = json.loads(l2_path.read_text())
    except Exception:
        return []
    findings = []
    for item in data.get("findings", []):
        sev  = item.get("severity", MEDIUM).upper()
        cat  = item.get("category", "runtime")
        det  = item.get("detail", "")
        path = item.get("file_path", "")
        findings.append(Finding(sev if sev in SEVERITY_ORDER else MEDIUM, cat, det, path))
    return findings


# ── Permissions inference ─────────────────────────────────────────────────────

def infer_permissions(findings: list[Finding], policy: dict) -> dict:
    """
    Returns a dict of permission categories → {status, reason, policy_decision}.
    status: "allowed" | "blocked" | "warned" | "undeclared" | "clean"
    """

    cats = {f.category for f in findings}
    sev_map: dict[str, str] = {}  # category → worst severity
    for f in findings:
        if f.category not in sev_map or \
                SEVERITY_ORDER.index(f.severity) < SEVERITY_ORDER.index(sev_map[f.category]):
            sev_map[f.category] = f.severity

    def _has(*categories: str) -> bool:
        return bool(cats & set(categories))

    net_cfg   = policy.get("network", {})
    cmd_cfg   = policy.get("command_execution", {})
    destr_cfg = policy.get("destructive_ops", {})
    priv_cfg  = policy.get("privilege_escalation", {})

    perms: dict[str, dict] = {}

    # Network
    if _has("network"):
        if not net_cfg.get("allow", True):
            perms["network"] = {"status": "blocked",
                                "reason": "network calls detected; policy disallows network",
                                "severity": sev_map.get("network", HIGH)}
        elif net_cfg.get("block_if_undeclared", False):
            perms["network"] = {"status": "blocked",
                                "reason": "undeclared network access (strict policy)",
                                "severity": sev_map.get("network", HIGH)}
        else:
            perms["network"] = {"status": "warned",
                                "reason": "network calls detected — verify intent",
                                "severity": sev_map.get("network", MEDIUM)}
    else:
        perms["network"] = {"status": "clean", "reason": "no network calls detected", "severity": INFO}

    # Shell / code execution
    if _has("code_exec", "dynamic_execution"):
        if not cmd_cfg.get("allow", True):
            perms["shell_exec"] = {"status": "blocked",
                                   "reason": "command execution detected; policy disallows",
                                   "severity": sev_map.get("code_exec", CRITICAL)}
        else:
            perms["shell_exec"] = {"status": "warned",
                                   "reason": "dynamic code execution detected — requires approval",
                                   "severity": sev_map.get("code_exec", HIGH)}
    else:
        perms["shell_exec"] = {"status": "clean", "reason": "no dynamic execution detected", "severity": INFO}

    # Secrets / sensitive paths
    if _has("secrets", "ioc"):
        perms["secrets_access"] = {"status": "blocked",
                                   "reason": "accesses sensitive credential paths",
                                   "severity": CRITICAL}
    else:
        perms["secrets_access"] = {"status": "clean", "reason": "no sensitive path access", "severity": INFO}

    # Data exfiltration
    if _has("data_exfil"):
        perms["data_exfiltration"] = {"status": "blocked",
                                      "reason": "data exfiltration pattern detected",
                                      "severity": CRITICAL}
    else:
        perms["data_exfiltration"] = {"status": "clean", "reason": "no exfiltration patterns", "severity": INFO}

    # Destructive operations
    if _has("destructive"):
        if not destr_cfg.get("allow", False):
            perms["destructive_ops"] = {"status": "blocked",
                                        "reason": "destructive filesystem operations detected",
                                        "severity": HIGH}
        else:
            perms["destructive_ops"] = {"status": "warned",
                                        "reason": "destructive operations — policy allows with warning",
                                        "severity": MEDIUM}
    else:
        perms["destructive_ops"] = {"status": "clean", "reason": "no destructive ops", "severity": INFO}

    # Privilege escalation
    if _has("privilege"):
        if not priv_cfg.get("allow", False):
            perms["privilege_escalation"] = {"status": "blocked",
                                             "reason": "privilege escalation detected (sudo/chmod 777)",
                                             "severity": HIGH}
        else:
            perms["privilege_escalation"] = {"status": "warned",
                                             "reason": "privilege escalation — policy allows with warning",
                                             "severity": MEDIUM}
    else:
        perms["privilege_escalation"] = {"status": "clean", "reason": "no privilege escalation", "severity": INFO}

    # Persistence mechanisms
    if _has("persistence", "install_hook"):
        perms["persistence"] = {"status": "warned",
                                "reason": "modifies shell profiles or installs hooks",
                                "severity": HIGH}
    else:
        perms["persistence"] = {"status": "clean", "reason": "no persistence mechanisms", "severity": INFO}

    # Symlink escape
    if _has("symlink_escape"):
        perms["symlink_escape"] = {"status": "blocked",
                                   "reason": "symlinks escape skill directory boundary",
                                   "severity": CRITICAL}
    else:
        perms["symlink_escape"] = {"status": "clean", "reason": "no symlink escapes", "severity": INFO}

    # Malicious packages / CVEs
    if _has("malicious_package"):
        perms["supply_chain"] = {"status": "blocked",
                                 "reason": "known malicious package(s) in dependencies",
                                 "severity": CRITICAL}
    elif _has("cve"):
        perms["supply_chain"] = {"status": "warned",
                                 "reason": "CVEs found in dependencies",
                                 "severity": HIGH}
    else:
        perms["supply_chain"] = {"status": "clean", "reason": "no supply chain issues", "severity": INFO}

    return perms


def overall_result(findings: list[Finding], policy: dict) -> str:
    sevs = {f.severity for f in findings}
    if CRITICAL in sevs:
        return "BLOCKED"
    if HIGH in sevs and policy.get("block_on_high", False):
        return "BLOCKED"
    if HIGH in sevs or MEDIUM in sevs:
        return "WARN"
    return "OK"


# ── Report writers ────────────────────────────────────────────────────────────

STATUS_ICON = {
    "blocked":     "🚫",
    "warned":      "⚠️ ",
    "undeclared":  "❓",
    "clean":       "✅",
    "allowed":     "✅",
}

PERM_LABEL = {
    "network":              "Network Access",
    "shell_exec":           "Shell / Code Exec",
    "secrets_access":       "Secrets & Credentials",
    "data_exfiltration":    "Data Exfiltration",
    "destructive_ops":      "Destructive Operations",
    "privilege_escalation": "Privilege Escalation",
    "persistence":          "Persistence Mechanisms",
    "symlink_escape":       "Symlink Escape",
    "supply_chain":         "Supply Chain",
}


def write_permissions_md(path: Path, skill: str, version: str,
                         perms: dict, profile: str, timestamp: str) -> None:
    lines = [
        f"# Permissions Declaration — {skill} v{version}",
        f"",
        f"| Category | Status | Severity | Notes |",
        f"|----------|--------|----------|-------|",
    ]
    for key, data in perms.items():
        label  = PERM_LABEL.get(key, key.replace("_", " ").title())
        icon   = STATUS_ICON.get(data["status"], "❓")
        sev    = data.get("severity", INFO)
        reason = data.get("reason", "")
        sev_icon = SEVERITY_ICON.get(sev, "")
        lines.append(f"| {label} | {icon} {data['status'].upper()} | {sev_icon} {sev} | {reason} |")

    lines += [
        "",
        f"> Policy profile: **{profile}**  ",
        f"> Generated by SkillGate at {timestamp}",
    ]
    path.write_text("\n".join(lines) + "\n")


def write_report_md(path: Path, skill: str, version: str, result: str,
                    findings: list[Finding], perms: dict,
                    profile: str, timestamp: str) -> None:

    result_icon = {"BLOCKED": "❌", "WARN": "⚠️", "OK": "✅"}.get(result, "?")

    # Group findings by category
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    # Count by severity
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"# SkillGate Security Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Skill | `{skill}` |",
        f"| Version | `{version}` |",
        f"| Profile | `{profile}` |",
        f"| Result | {result_icon} **{result}** |",
        f"| Generated | {timestamp} |",
        f"",
        f"## Finding Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {counts[sev]} |")
    if not findings:
        lines.append("| ✅ | 0 findings — no issues detected |")

    lines += ["", "## Permissions Overview", ""]
    for key, data in perms.items():
        label = PERM_LABEL.get(key, key.replace("_", " ").title())
        icon  = STATUS_ICON.get(data["status"], "?")
        lines.append(f"- **{label}**: {icon} {data['status'].upper()} — {data['reason']}")

    if findings:
        lines += ["", "## Detailed Findings", ""]
        for cat, cat_findings in sorted(by_cat.items()):
            lines.append(f"### {cat.replace('_', ' ').title()}")
            for f in sorted(cat_findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                icon = SEVERITY_ICON.get(f.severity, "")
                fp = f" `{f.file_path}`" if f.file_path else ""
                lines.append(f"- {icon} **{f.severity}**: {f.detail}{fp}")
            lines.append("")

    lines += [
        "## Remediation",
        "",
    ]
    blocked_perms = [k for k, v in perms.items() if v["status"] == "blocked"]
    warned_perms  = [k for k, v in perms.items() if v["status"] == "warned"]

    if blocked_perms:
        lines.append("**Required before admission:**")
        for key in blocked_perms:
            label = PERM_LABEL.get(key, key)
            lines.append(f"- Remove or justify: {label} ({perms[key]['reason']})")
        lines.append("")
    if warned_perms:
        lines.append("**Requires human review:**")
        for key in warned_perms:
            label = PERM_LABEL.get(key, key)
            lines.append(f"- Review: {label} ({perms[key]['reason']})")
        lines.append("")
    if not blocked_perms and not warned_perms:
        lines.append("No remediation required.")

    path.write_text("\n".join(lines) + "\n")


def write_report_json(path: Path, skill: str, version: str, result: str,
                      findings: list[Finding], perms: dict,
                      profile: str, timestamp: str) -> None:
    data = {
        "skill":      skill,
        "version":    version,
        "profile":    profile,
        "timestamp":  timestamp,
        "result":     result,
        "finding_counts": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in SEVERITY_ORDER
        },
        "permissions": {
            k: {
                "status":   v["status"],
                "severity": v.get("severity", INFO),
                "reason":   v.get("reason", ""),
            }
            for k, v in perms.items()
        },
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_name")
    ap.add_argument("version")
    ap.add_argument("out_dir",     help="intake out_dir containing l1_findings.md etc.")
    ap.add_argument("--policy",    default=str(DEFAULT_POLICY))
    ap.add_argument("--profile",   default=None,
                    help="balanced|strict (default: from policy.yaml)")
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args()

    out_dir  = Path(args.out_dir)
    if not out_dir.exists():
        print(f"out_dir not found: {out_dir}", file=sys.stderr)
        return 1

    # Determine profile
    policy_path = Path(args.policy)
    profile = args.profile
    if profile is None:
        if _YAML_OK and policy_path.exists():
            with open(policy_path) as f:
                raw = yaml.safe_load(f)
            profile = raw.get("default_profile", "balanced")
        else:
            profile = "balanced"

    policy = load_policy(policy_path, profile)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Parse all available scan results
    findings: list[Finding] = []
    findings += parse_l1_findings(out_dir / "l1_findings.md")
    findings += parse_semgrep(out_dir / "semgrep.json")
    findings += parse_l2_report(out_dir / "l2_report.json")

    # Deduplicate: same (severity, category, detail)
    seen: set[tuple] = set()
    deduped = []
    for f in findings:
        key = (f.severity, f.category, f.detail[:80])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    perms  = infer_permissions(findings, policy)
    result = overall_result(findings, policy)

    # Destination: reports/<skill_name>/
    report_dir = Path(args.reports_dir) / args.skill_name
    report_dir.mkdir(parents=True, exist_ok=True)

    write_permissions_md(
        report_dir / "PERMISSIONS.md",
        args.skill_name, args.version, perms, profile, timestamp,
    )
    write_report_md(
        report_dir / "report.md",
        args.skill_name, args.version, result, findings, perms, profile, timestamp,
    )
    write_report_json(
        report_dir / "report.json",
        args.skill_name, args.version, result, findings, perms, profile, timestamp,
    )

    print(f"[report] result={result}  profile={profile}  findings={len(findings)}")
    print(f"[report] output → {report_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
