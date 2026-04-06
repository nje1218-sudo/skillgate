# PERMISSIONS — `healthcheck` v0.0.0

> Policy: **balanced** v0.1  
> Scan: 2026-04-06T14:51:12Z  
> Result: ❌ BLOCKED

## Risk Summary

| Category | Status | Risk | Notes |
|----------|--------|------|-------|
| Network | VIOLATION | 🟠 HIGH | network calls detected (2 hit(s)) |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (1 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 1 undeclared tool(s) imported |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Details

### Network
- **Policy**: `allow.network: False`
- **Detected**: yes
  - `scripts/policy_check.py`: `curl`
  - `scripts/policy_check.py`: `wget`

### Exec / Subprocess
- **Policy**: `allow.exec: False`
- **Detected**: yes
  - `scripts/generate_report.py`: `os.system`

### Tools / Imports
- **Policy declares**: `[]`
- **Detected imports**: `['yaml']`
- **Undeclared**: `['yaml']`

### Read Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
- **Policy deny**: `['/home/node/.openclaw/secrets', '/home/node/.ssh', '/etc', '/root', '/proc', '/sys']`
  - ✅ all reads within policy

### Write Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
  - ✅ no write operations detected

