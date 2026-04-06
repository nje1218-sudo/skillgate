# SkillGate Report — `tmpk08rssz9` v0.0.0

| | |
|---|---|
| Policy | `balanced` v0.1 |
| Result | ⚠️ **WARN** |
| Timestamp | 2026-04-06T19:24:05Z |

## Permission Evaluation

| Category | Status | Risk | Detail |
|----------|--------|------|--------|
| Network | OK | ✅ CLEAN | no network calls detected |
| Exec / Subprocess | OK | ✅ CLEAN | no exec/subprocess detected |
| Tools / Imports | OK | ✅ CLEAN | all imported tools declared in policy |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Remediation

**Requires human review:**
- Static Scanner Gate: static scanner found suspicious patterns


## Raw Scanner Output

```

### policy_check.py
BLOCK_VIOLATIONS:
- network_exec: /tmp/tmpk08rssz9/tests/skill.py
- decode_and_run: /tmp/tmpk08rssz9/tests/skill.py


### check-dangerous-commands.py
🔴 [BLOCK]
  - dynamic_execution: /tmp/tmpk08rssz9/tests/skill.py
🟠 [REQUIRE_APPROVAL]
  - config_modification: /tmp/tmpk08rssz9/tests/skill.py


### check-ioc.py
🟠 [WARN — SUSPICIOUS PATTERN]
  - suspicious pattern 'exec\(' in: /tmp/tmpk08rssz9/tests/skill.py


### check-dependencies.py
OK: no dependency manifests found


```

