# SkillGate 🛡️

AI Agent Security Scanner for OpenClaw — Detect malicious skills before installation.

## Why SkillGate?

AI agent skills can contain:
- Prompt injection attacks
- Credential exfiltration
- Hidden command execution
- Supply chain backdoors

**SkillGate** provides automated security scanning before you install any skill.

## Features

### L1 - Static Analysis Scanner
| Scanner | Purpose |
|---------|---------|
| **Aguara** | 177+ rules for prompt injection, command execution, exfiltration |
| **Skill-Scanner** | Cisco CVE database + vulnerability detection |
| **Secrets-Scan** | Hardcoded API keys, tokens, credentials |
| **Structure-Check** | SKILL.md validation, dangerous patterns |

### L2 - Runtime Sandbox (coming soon)
- Behavioral analysis
- Network call monitoring
- File system access control

## Installation

```bash
# Clone to your OpenClaw skills directory
git clone https://github.com/nje1218-sudo/SkillGate.git ~/.openclaw/skills/skill-gate
```

## Usage

```bash
# Scan a skill
bash ~/.openclaw/skills/skill-gate/skill-vetter/scripts/vett.sh <skill-path>

# Or use our wrapped skill
python ~/.openclaw/skills/skill-gate/skill-scanner/scan.py <skill-path>
```

## Output

| Verdict | Action |
|---------|--------|
| **BLOCKED** | Do NOT install |
| **REVIEW** | Manual check required |
| **SAFE** | Proceed with installation |

## Documentation

- [SOP](./sops/skill-download-vetting-sop.md) — Full vetting workflow
- [Templates](./SkillGate/templates/) — Report templates, incident response
- [Strategy](./SkillGate/strategy/) — Market positioning, pricing

## License

MIT