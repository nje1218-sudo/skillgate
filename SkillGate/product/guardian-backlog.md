# SkillGate Guardian / Reliability Backlog

這份文件收納 **目前不放進第一本 SkillGate 核心電子書**，但之後非常適合延伸成：

- SkillGate Guardian handbook
- OpenClaw reliability playbook
- incident response / runtime ops 產品線

---

## 為什麼先不放進第一本
第一本書目前聚焦在：
- skill / plugin 安全門禁
- L1 / L2 vetting
- 權限宣告
- 外連風險
- 報告包
- Policy-as-Code
- Diff Gate

以下這些內容雖然有價值，但更偏 **runtime reliability / ops / incident management**，放進第一本會讓主線失焦。

---

## Backlog Topics

### 1. Memory、Provider、Gateway：三個最容易爆炸的地方
#### 可寫內容
- memory_search 假健康與真故障的判斷方式
- embedding/provider misconfiguration 常見坑
- OpenAI-compatible / Ollama / Gemini / Jina 等 provider 行為差異
- gateway unreachable / timeout 的診斷順序
- channel OK 與 runtime OK 的差別
- session noise / repeated inbound 對穩定性的影響

#### 可變成的資產
- runtime triage guide
- provider troubleshooting matrix
- memory health checklist

---

### 2. OpenClaw Doctor / Watchdog 該怎麼設計
#### 可寫內容
- generic restart 腳本為什麼沒價值
- diagnose / repair / report 三段式
- 哪些修復動作可自動做、哪些不能
- 可逆修復與 rollback 設計
- status / probes / model-provider / channel / memory 的健康分類
- incident confidence score 與 remaining issues

#### 可變成的資產
- doctor MVP spec
- watchdog design note
- diagnose → action map

---

### 3. Heartbeat、Cron、Session Hygiene
#### 可寫內容
- heartbeat 為什麼不只是提醒器，而是 auditor + continuation trigger
- cron 與 heartbeat 的分工
- session transcript 汙染與重複 inbound 問題
- done / blocked / deferred / sent-awaiting-ack 任務狀態模型
- 如何降低 agent 卡住、亂追、重複提醒

#### 可變成的資產
- heartbeat framework
- session hygiene checklist
- task-state model template

---

### 4. Incident Report 與 Incident Log
#### 可寫內容
- incident report 應該記什麼、不該記什麼
- root cause / trigger / action taken / unresolved risks
- trace + redaction 的必要性
- JSONL incident log 與事後回顧
- incident report 如何回流成產品規則

#### 可變成的資產
- incident report template
- incident log JSON schema
- postmortem checklist

---

## 產品化方向
這些 backlog 之後可拆成三條線：

### A. SkillGate Guardian Handbook
- 給正在跑 OpenClaw / agents 的 builder
- 聚焦 reliability / watchdog / self-healing

### B. OpenClaw Reliability Playbook
- 偏教學與操作手冊
- 可作為第二本書或高價 bundle

### C. Agent Incident Response Handbook
- 偏團隊化 / 可稽核 / incident 流程
- 更接近 B2B / 團隊導向產品

---

## 和第一本電子書的關係
### 第一本：SkillGate Core
- 安全門禁
- skill 入庫
- vetting
- reports
- governance

### 第二層內容：Guardian / Reliability
- doctor
- watchdog
- heartbeat / cron
- incident response
- runtime ops

也就是：
**第一本賣 gate；第二本賣 runtime。**

---

## 後續建議
1. 第一本文案與目錄先聚焦，不再混入 runtime 章節
2. backlog 主題逐步整理成模板 / checklist / spec
3. 等第一本賣出後，再看哪個 runtime 痛點最值得升級成第二本或工具
