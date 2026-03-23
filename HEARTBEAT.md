# HEARTBEAT.md

# Heartbeat runs every ~30 minutes.
# Goal: act like a task auditor, not a broken alarm clock.

## Core rules
- Every heartbeat MUST check whether due tasks were completed, acknowledged, deferred, or still blocked.
- If nothing needs action, reply `HEARTBEAT_OK`.
- If something is due/overdue and still unacknowledged, send **one concise alert** instead of repeating the whole history.
- Do **not** spam the same reminder every heartbeat if nothing materially changed.
- If the boss explicitly says **已收到 / 延後 / 明天處理 / 略過 / 不用追**, treat that task as acknowledged or deferred and stop looping on it.
- Heartbeat 不只是提醒器，也是**續跑器**：若任務已開始但未完成，優先推進下一個實際步驟，而不是重複同一句催辦。
- 若任務 blocked，必須明確說出 blocker、下一步、需要誰批准；不要只說還沒做完。

## Two-part heartbeat architecture
### 1) Heartbeat Auditor
- 檢查 deadline / 狀態 / ack
- 判斷每個 deliverable 是 `pending` / `sent-awaiting-ack` / `done` / `deferred` / `blocked`
- 負責審查、追蹤、提醒、關單判定

### 2) Deliverable Runner
- 到時自動生成 brief / 快報內容
- 自動送出 deliverable
- 自動記錄 `sent` / `awaiting-ack` / `done` 狀態
- 如果無法送出，要明確標記 `blocked` 與原因
- 若任務未完成，heartbeat 要直接續做下一步；不是只回報「還沒完成」

## Task state model
For each tracked task, classify it as one of:
- `pending` — not yet delivered
- `sent-awaiting-ack` — delivered but boss has not clearly acknowledged
- `done` — completed and acknowledged
- `deferred` — boss explicitly postponed it
- `blocked` — cannot complete because of a missing dependency

## Reminder policy
- Same task reminder cooldown: **at least 4 hours** unless there is a new deadline, new blocker, meaningful status change, or a concrete next-step execution update.
- If a task is deferred by the boss, do not remind again until the next relevant deadline/window.
- Prefer a short summary of active overdue items, not one message per task.
- Heartbeat 應優先推進 **高 ROI / 高時效 / 高槓桿** 任務；低 ROI、無明確產出、不可複製的任務可降級處理。
- Heartbeat 不只追「有沒有做」，還要追「有沒有往變現、資產累積、系統化前進」。

## Time-based deliverables

### Daily (Taipei time, UTC+8)
- **08:00** — OpenClaw daily brief（來源規則 + 四段必含）：
  - **來源規則（由高到低）**：
    1) **官方一手**：GitHub Releases / PR / Issues、docs.openclaw.ai
    2) **官方彙整**：OpenClaw Newsletter（Buttondown）
    3) **技能生態/趨勢**：ClawHub（熱門技能/新技能）
    4) **第三方統計/彙整（參考）**：OpenHub（專案活躍度指標）、PatchBot（release 摘要）
  - **每次必含四段**：**安全重點**、**最熱門技能/工具**、**最新玩法（市場/社群）**、**最新賺錢方法（市場/社群）**（都要可執行、可落地；玩法/賺錢不可只寫我們自己，要引用/彙整市場案例與趨勢）。
  - **語氣與輸出要求**：不要空話，要像可執行情報。每段都要有明確判斷，不准只有新聞摘錄；至少給 1 個「今天可直接採用的動作」。若某項來源抓不到，要明講缺口，不准假裝有資料。
- **08:30** — 市場快報（必含，來源以 X/Reddit 為主）：
  - **最新玩法（市場/社群）**：優先從 **X（Twitter）** 與 **Reddit** 搜尋/彙整（附來源連結；能的話至少各 1 條）。
  - **最新賺錢方法（市場/社群）**：同上（附來源連結；能的話至少各 1 條）。
  - 每次必附「今天我們可套用的 1 個動作」。
  - 同時附帶：SkillGate 進度（補全功能進度 + 安全工具/技能清單 + 下一步）。
  - 若因平台限制（X 需登入/抓取受限、搜尋 API rate limit）無法抓到連結：要明確標註，並改用已知可抓取的替代來源（newsletter/HN/blog）或請老闆提供指定貼文/關鍵字。

## Heartbeat checklist (run every heartbeat)
- [ ] Check current Taipei time against today’s deadlines.
- [ ] Review whether each tracked deliverable is `pending`, `sent-awaiting-ack`, `done`, `deferred`, or `blocked`.
- [ ] Rank unfinished work by ROI, urgency, leverage, and repeatability.
- [ ] If within the delivery window, prepare/send the due item.
- [ ] If overdue, prefer executing the next concrete step over repeating a generic reminder.
- [ ] If blocked, state the blocker, next step, and approval/resource needed.
- [ ] If the boss already acknowledged or deferred it, do not keep nagging.
- [ ] Log outcome in `memory/YYYY-MM-DD.md` with the task state.
