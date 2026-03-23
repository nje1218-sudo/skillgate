---
name: skill-scanner
version: 1.0.0
user-invocable: true
description: "Cisco AI skill scanner with CVE database. Triggers when: user wants to scan skills for vulnerabilities, malicious patterns, or known CVEs."
---

# Skill Scanner

Wrapper for Cisco AI Skill Scanner. Creates isolated venv on first use.

## When to Use

- After skill-vetter passes, for deeper CVE scan
- When user requests "full scan" or "enterprise scan"
- For compliance/audit requirements

## Installation

This skill auto-installs dependencies on first run:
```bash
# Creates venv at ~/.openclaw/venvs/skill-scanner
# Installs cisco-ai-skill-scanner
```

## How to Run

```bash
python ~/.openclaw/skills/skill-scanner/scan.py <skill-path-or-url>
```

## Arguments

- `<skill-path-or-url>` — Local path, GitHub URL, or ClawHub skill name

## Output

| Severity | Meaning |
|----------|---------|
| critical | CVE 漏洞，必須擋 |
| high | 重要風險 |
| medium | 建議 review |
| low | 資訊參考 |

## Example

```bash
# Scan local skill
skill-scanner scan ~/.openclaw/skills/tavily-search

# Scan GitHub repo
skill-scanner scan https://github.com/user/repo
```

## Requirements

- Python 3.8+
- Creates: ~/.openclaw/venvs/skill-scanner/
