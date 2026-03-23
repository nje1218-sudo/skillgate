# Default SkillGate Policy（外連白名單 + secrets deny）

> 目標：把「下載/試跑 skills」變成預設安全；要外連、要讀敏感檔，都必須先明列再放行。

## A) Network / Egress（預設全封）
- **Default: DENY ALL egress**
- 任何 skill 若必須連網：
  1) 先提出 allowlist（domain + port + protocol + reason）
  2) L2 sandbox 僅開 allowlist
  3) 報告必附：實際外連目的地（含 DNS resolve 結果）與請求類型（GET/POST、payload 摘要）

### Allowlist 範本
- `api.tavily.com:443 (tavily-search: web search/extract)`
- `clawhub.ai:443 (僅下載/查版本；不允許 runtime exfil)`
- `api.github.com:443 (僅抓 release/contents；不允許提交 secrets)`

## B) Filesystem（預設禁止敏感路徑）
- **Explicitly DENY（不准碰）**
  - `secrets/**`
  - `~/.ssh/**`
  - `~/.aws/**`
  - `~/.config/**`（除非明列子路徑）
  - `**/*.pem`, `**/*.key`, `**/*id_rsa*`
- 若技能確實需要讀某配置：
  - 必須改成「最小路徑」allow（例如只允許讀 `workspace/config/<skill>.json`）

## C) Exec / Dynamic code（預設高風險）
- 命中下列任一 → **強制升級審查（至少 L1，通常要 L2）**
  - `curl/wget` 下載後立刻執行
  - `eval()` / `exec()` / `Function()` 等動態執行
  - `postinstall` / `preinstall` scripts
  - base64 decode-and-run

## D) Observability（必須可稽核）
- 每次入庫必產出：
  - L1：可疑字串/外連/執行點（檔名+行號+snippet）
  - L2：檔案讀寫路徑清單、外連嘗試清單（目的地/頻率/協議）
  - 最終結論：Deploy / Deploy w/ Monitor / Block
