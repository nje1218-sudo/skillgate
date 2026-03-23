# SkillGate MVP Scope

更新時間：2026-03-15

## 產品目標
先做出一個可 demo、可驗證需求、可支撐第一批 design partner 對話的 MVP。

## 核心承諾
在第三方 skill / plugin 進 production 前，先完成：
- 審查
- 限權
- 留痕

## MVP In Scope

### 1. Skill Intake
- 接收 skill 原始碼 / 套件 / repo 來源
- 填入名稱、版本、作者、來源、授權

### 2. L1 Static Vetting
- 規則掃描
- 危險 pattern 偵測
- secrets / 外連 / exec / eval 類風險標記
- 以 **skill-vetting** 作為第一層核心掃描引擎之一
- 補上 source metadata parsing、manifest / permission inspection、dependency / license inspection、risk summary generation

### 3. L2 Sandbox Runtime Check
- 在受限環境執行
- 觀察檔案存取、網路外連、命令執行、異常行為

### 4. Policy Decision
- allow
- allow-with-restrictions
- reject

### 5. Trusted Registry
- 保存審查決策、版本、hash、權限設定與備註

### 6. Audit Report Export
- 輸出人類可讀報告
- 包含發現、風險摘要、決策與建議限制

## MVP Out of Scope
- reputation scoring
- SkillGraph
- 自動 diff gate
- 自動 rollback / quarantine
- ML anomaly detection
- 多租戶 RBAC
- 企業級 dashboard

## 成功標準
1. 能成功跑完一條完整流程：upload → vet → sandbox → decide → store → report
2. 能對至少 3 個示範 skill 產出合理報告
3. 報告足夠讓人類做 go / no-go 判斷
4. 能清楚展示 allow / restricted / reject 三種結果

## Demo 成功條件
- 5 分鐘內可講完完整價值
- 可展示至少一個被拒絕案例
- 可展示至少一個被限權通過案例
- 可展示 registry 與報告輸出

## 一句總結
**MVP 的任務不是做完整平台，而是證明 SkillGate 能把 skill 上線前的風險判斷流程產品化。**
