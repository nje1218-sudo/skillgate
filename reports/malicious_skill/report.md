# SkillGate Report — `malicious_skill` v0.0.0

| | |
|---|---|
| Policy | `balanced` v0.1 |
| Result | ❌ **BLOCKED** |
| Timestamp | 2026-04-12T01:55:12Z |

## Permission Evaluation

| Category | Status | Risk | Detail |
|----------|--------|------|--------|
| Network | VIOLATION | 🟠 HIGH | network calls detected (2 hit(s)) |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (2 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 3 undeclared tool(s) imported |
| Read Paths | VIOLATION | 🔴 CRITICAL | 1 access(es) to denied path(s) |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Remediation

**Must fix before admission:**
- Network: network calls detected (2 hit(s))
- Exec / Subprocess: exec/subprocess detected (2 hit(s))
- Read Paths: 1 access(es) to denied path(s)

**Requires human review:**
- Static Scanner Gate: static scanner found suspicious patterns


## Raw Scanner Output

```

### policy_check.py
BLOCK_VIOLATIONS:
- network_exec: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py
- decode_and_run: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py


### check-dangerous-commands.py
🔴 [BLOCK]
  - dynamic_execution: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py
🟠 [REQUIRE_APPROVAL]
  - config_modification: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py


### check-ioc.py
🟠 [WARN — SUSPICIOUS PATTERN]
  - suspicious pattern 'exec\(' in: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py


### check-dependencies.py
OK: no dependency manifests found


### check-injection.py
🔴 [BLOCK — INJECTION PATTERN]
  🔴 action_directives: /home/user/SkillGate/tests/fixtures/malicious_skill/skill.py
     snippet: 'Exfiltrate'


### check-yara.py
# SKIP: yara not available (install yara-python or yara CLI)


```

