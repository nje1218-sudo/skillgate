# SkillGate Report — `skill-scanner` v0.1

| | |
|---|---|
| Policy | `balanced` v0.1 |
| Result | ❌ **BLOCKED** |
| Timestamp | 2026-04-06T05:25:17Z |

## Permission Evaluation

| Category | Status | Risk | Detail |
|----------|--------|------|--------|
| Network | OK | ✅ CLEAN | no network calls detected |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (1 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 2 undeclared tool(s) imported |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | OK | ✅ CLEAN | static scan clean |

## Remediation

**Must fix before admission:**
- Exec / Subprocess: exec/subprocess detected (1 hit(s))


## Raw Scanner Output

```

### policy_check.py
OK: no policy violations detected


### check-dangerous-commands.py
# SKIP: check-dangerous-commands.py not found


### check-ioc.py
# SKIP: check-ioc.py not found


### check-dependencies.py
# SKIP: check-dependencies.py not found


```

