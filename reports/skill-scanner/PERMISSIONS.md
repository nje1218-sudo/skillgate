# PERMISSIONS — `skill-scanner` v0.1

> Policy: **balanced** v0.1  
> Scan: 2026-04-06T05:25:17Z  
> Result: ❌ BLOCKED

## Risk Summary

| Category | Status | Risk | Notes |
|----------|--------|------|-------|
| Network | OK | ✅ CLEAN | no network calls detected |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (1 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 2 undeclared tool(s) imported |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | OK | ✅ CLEAN | static scan clean |

## Details

### Network
- **Policy**: `allow.network: False`
- **Detected**: no

### Exec / Subprocess
- **Policy**: `allow.exec: False`
- **Detected**: yes
  - `scan.py`: `subprocess.run`

### Tools / Imports
- **Policy declares**: `[]`
- **Detected imports**: `['subprocess', 'venv']`
- **Undeclared**: `['subprocess', 'venv']`

### Read Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
- **Policy deny**: `['/home/node/.openclaw/secrets', '/home/node/.ssh', '/etc', '/root', '/proc', '/sys']`
  - ✅ all reads within policy

### Write Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
  - ✅ no write operations detected

