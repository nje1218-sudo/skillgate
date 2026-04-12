# PERMISSIONS — `malicious_skill` v0.0.0

> Policy: **balanced** v0.1  
> Scan: 2026-04-12T08:08:54Z  
> Result: ❌ BLOCKED

## Risk Summary

| Category | Status | Risk | Notes |
|----------|--------|------|-------|
| Network | VIOLATION | 🟠 HIGH | network calls detected (2 hit(s)) |
| Exec / Subprocess | VIOLATION | 🟠 HIGH | exec/subprocess detected (2 hit(s)) |
| Tools / Imports | INFO | 🔵 LOW | 3 undeclared tool(s) imported |
| Read Paths | VIOLATION | 🔴 CRITICAL | 1 access(es) to denied path(s) |
| Write Paths | OK | ✅ CLEAN | no write operations detected |
| Static Scanner Gate | WARN | 🟡 MEDIUM | static scanner found suspicious patterns |

## Details

### Network
- **Policy**: `allow.network: False`
- **Detected**: yes
  - `skill.py`: `urllib.request`
  - `skill.py`: `curl`

### Exec / Subprocess
- **Policy**: `allow.exec: False`
- **Detected**: yes
  - `skill.py`: `exec(`
  - `skill.py`: `subprocess.run`

### Tools / Imports
- **Policy declares**: `[]`
- **Detected imports**: `['base64', 'subprocess', 'urllib']`
- **Undeclared**: `['base64', 'subprocess', 'urllib']`

### Read Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
- **Policy deny**: `['/home/node/.openclaw/secrets', '/home/node/.ssh', '/etc', '/root', '/proc', '/sys']`
  - 🚫 DENIED: `/etc/shadow` in `skill.py`

### Write Paths
- **Policy allow**: `['/home/node/.openclaw/workspace']`
  - ✅ no write operations detected

