# PERMISSIONS — healthcheck（我們自家版）

> 入庫必備；升版必須 diff；權限變大＝重新審。

## 1) Filesystem
### Allowed READ
- `/home/node/.openclaw/workspace/**`（含 `AGENTS.md` / `SOUL.md` / `MEMORY.md` / `sops/**` / `memory/**`）
- OpenClaw logs / config（依實際部署填寫）：
  - `<TBD>`

### Allowed WRITE
- `/home/node/.openclaw/workspace/memory/**`（寫入每日健檢紀錄）
- `/home/node/.openclaw/workspace/reports/**`（輸出報告/差異檔）

### Explicitly DENY
- `secrets/**`（除非另行批准並明列路徑）
- `~/.ssh/**`
- 任何家目錄下的憑證/金鑰預設禁止

## 2) Network / Egress
- **Default: DENY ALL**
- Allowlist（如必須外連才填）：
  - `<domain>:<port> (<reason>)`

## 3) Tool Capabilities
### Allowed
- `read`
- `exec`（僅允許唯讀指令；涉及變更需二次確認）

### Requires explicit approval per run
- 任何會改動系統狀態的指令（升版、重啟服務、刪檔、改 config）

### Not allowed by default
- `browser`
- `nodes`
- 任何對外發訊/上傳（除非你明確指示）

## 4) Telemetry / Observability
- 必須：trace + redaction
- 日誌不得包含：tokens/keys/PII（若偵測到必須遮罩後再落盤）
