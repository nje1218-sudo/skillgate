# SkillGate Report — `healthcheck` v0.0.0

| | |
|---|---|
| Policy | `balanced` v0.1 |
| Result | ❌ **BLOCKED** |
| Timestamp | 2026-04-06T14:51:12Z |

## Permission Evaluation

| Category | Status | Risk | Detail |
|----------|--------|------|--------|
| Network | VIOLATION | 🟠 HIGH | network calls detected (2 hit(s)) |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (1 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 1 undeclared tool(s) imported |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Remediation

**Must fix before admission:**
- Network: network calls detected (2 hit(s))
- Exec / Subprocess: exec/subprocess detected (1 hit(s))

**Requires human review:**
- Static Scanner Gate: static scanner found suspicious patterns


## Raw Scanner Output

```

### policy_check.py
BLOCK_VIOLATIONS:
- network_exec: /home/user/SkillGate/skills/healthcheck/references/DEFAULT_SKILLGATE_POLICY.md
- decode_and_run: /home/user/SkillGate/skills/healthcheck/references/DEFAULT_SKILLGATE_POLICY.md
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/references/DEFAULT_SKILLGATE_POLICY.md
- network_exec: /home/user/SkillGate/skills/healthcheck/references/policy.yaml
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/references/policy.yaml
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/references/PERMISSIONS.md
- network_exec: /home/user/SkillGate/skills/healthcheck/references/CORPUS_CASES.md
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/references/CORPUS_CASES.md
- network_exec: /home/user/SkillGate/skills/healthcheck/scripts/policy_check.py
- decode_and_run: /home/user/SkillGate/skills/healthcheck/scripts/policy_check.py
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/scripts/policy_check.py
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/scripts/generate_report.py
- secrets_path_reference: /home/user/SkillGate/skills/healthcheck/configs/policy.yaml
WARN_VIOLATIONS:
- install_hooks: /home/user/SkillGate/skills/healthcheck/references/DEFAULT_SKILLGATE_POLICY.md
- webhook_or_url: /home/user/SkillGate/skills/healthcheck/references/policy.yaml
- install_hooks: /home/user/SkillGate/skills/healthcheck/references/policy.yaml
- webhook_or_url: /home/user/SkillGate/skills/healthcheck/references/CORPUS_CASES.md
- webhook_or_url: /home/user/SkillGate/skills/healthcheck/scripts/policy_check.py
- install_hooks: /home/user/SkillGate/skills/healthcheck/scripts/policy_check.py


### check-dangerous-commands.py
# SKIP: check-dangerous-commands.py not found


### check-ioc.py
# SKIP: check-ioc.py not found


### check-dependencies.py
# SKIP: check-dependencies.py not found


```

