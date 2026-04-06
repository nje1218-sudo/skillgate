# PERMISSIONS — `tmpp4kqpegq` v0.0.0

> Policy: **balanced** v0.1  
> Scan: 2026-04-06T19:24:16Z  
> Result: ⚠️ WARN

## Risk Summary

| Category | Status | Risk | Notes |
|----------|--------|------|-------|
| Network | OK | ✅ CLEAN | no network calls detected |
| Exec / Subprocess | OK | ✅ CLEAN | no exec/subprocess detected |
| Tools / Imports | OK | ✅ CLEAN | all imported tools declared in policy |
| Read Paths | OK | ✅ CLEAN | all detected reads within allowed paths |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Details

### Network
- **Policy**: `allow.network: False`
- **Detected**: no

### Exec / Subprocess
- **Policy**: `allow.exec: False`
- **Detected**: no

### Tools / Imports
- **Policy declares**: `[]`
- **Detected imports**: `[]`

### Read Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
- **Policy deny**: `['/home/node/.openclaw/secrets', '/home/node/.ssh', '/etc', '/root', '/proc', '/sys']`
  - ✅ all reads within policy

### Write Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
  - ✅ no write operations detected

