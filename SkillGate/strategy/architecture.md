# SkillGate Architecture

## One-liner
SkillGate 是 OpenClaw / Agent Skills 生態的 **Security + Ops + Governance layer**。

一句話：
**讓 AI 系統更安全上線，讓 agent 能被放心用來賺錢，讓自動化不因技能/插件風險而翻車。**

安全不是終點；安全是讓自動化收入能成立的前提。

---

## 1. 架構總覽

```text
SkillGate
├─ A. 產品層（我們賣什麼）
├─ B. 整合能力層（我們用什麼能力來做）
├─ C. 內容層（我們如何獲客與教育市場）
├─ D. 驗證層（我們怎麼判斷市場值不值得做）
└─ E. 治理層（我們怎麼留下可稽核資產）
```

---

## 2. 產品層

### A1. 電子書
- 前端付費引流產品
- 驗證痛點、收名單、收第一筆錢
- 導流到模板包 / 審查服務 / SkillGate Guardian

### A2. 模板包
- L1 checklist
- L2 checklist
- `PERMISSIONS.md`
- 入庫報告模板
- 升版重審模板
- Diff Gate / Policy-as-Code 範本

### A3. 審查服務
- skill / plugin / memory plugin 安全審查
- L1 / L2 結論
- 報告包與 deploy 建議

### A4. 報告包 / 升版 Gate
- 入庫報告包
- 權限 diff
- 網路行為 diff
- 升版重審
- deploy / block / monitor 決策輸出

### A5. SkillGate Guardian
- 第二階段產品
- runtime reliability / watchdog / doctor / incident layer
- 不是第一本書主軸

---

## 3. 整合能力層

### B1. Vetting Engine
- skill-vetter / skill-auditor 類能力
- skill 來源、內容、危險指令、惡意模式快篩
- 作為 L1 Fast Gate 的基礎

### B2. Dependency Risk Layer
- dependency-auditor 類能力
- typosquatting
- publisher identity
- install hooks
- transitive dependency 風險
- vuln DB / advisories 參考
- license compatibility

### B3. Permission Governance Layer
- permission-auditor 類能力
- 權限解釋引擎
- 危險組合判定
- 最小權限建議
- 權限風險評分與報告欄位

### B4. Sandbox / Runtime Behavior Layer
- sandbox-guard / SecureClaw / 其他 sandbox engine
- Docker profile 只是其中一種
- 讀寫路徑、外連、child process、權限越界觀察
- L2 Deep Gate 的執行隔離模板

### B5. Network / Exfiltration Layer
- network-watcher 類能力
- endpoint allowlist / denylist
- 外連理由審查
- exfiltration pattern 檢查

### B6. Add-on Checks / Threat Intelligence
- YARA
- ClamAV
- SBOM / vuln intelligence
- IOC / domain / hash intelligence
- 其他可插拔 rule packs / malware/signature databases

---

## 4. 三層審查架構

### Layer 1 — Fast Gate
目標：在秒到分鐘級內，先快速把 80% 明顯風險篩掉。

內容：
- 來源 / 維護者 / 版本鎖定
- `postinstall` / `preinstall`
- `curl | bash` / `wget | sh`
- base64 decode-and-run
- 外連 / 裸 IP / webhook
- 權限面粗分
- 依賴風險快掃
- 惡意特徵關鍵字快掃

輸出：
- `Low risk`
- `Needs review`
- `Block`

### Layer 2 — Deep Gate
目標：對會碰核心能力或 Fast Gate 未通過的 skill 做深審。

內容：
- L2 sandbox / runtime behavior check
- dependency review
- permission fit analysis
- network / exfiltration review
- 報告輸出

輸出：
- `Deploy`
- `Deploy w/ Monitor`
- `Block`

### Layer 3 — Batch Mode
目標：大量 skill 下載場景下，不要每個都進人工深審。

流程：
- 先跑全部 skill 的 Fast Gate
- 分成：
  - A 桶：低風險候選
  - B 桶：Needs review
  - C 桶：直接 Block

賣點：
**先快速把 80% 明顯風險篩掉，再把 20% 真正危險的抓去深審。**

---

## 5. 內容層

### C1. SkillGate Core Ebook
第一本書，聚焦：
- 安全門禁
- L1 / L2 vetting
- 權限治理
- 報告包
- Policy-as-Code
- Diff Gate
- 產品化路線

### C2. 模板包內容
- checklist
- 報告模板
- 權限模板
- 升版重審模板

### C3. 後續 backlog
- runtime reliability
- doctor / watchdog
- incident response
- heartbeat / cron / session hygiene

---

## 6. 驗證層

固定市場驗證來源：
- TrustMRR
- OpenClaw 社群
- OpenClaw 技能討論區
- X（Twitter）討論度
- Reddit 討論
- 類似商品 / 類似服務
- 自己的 landing page / waitlist / preorder / 小額付費測試

原則：
- 不單押單一來源
- TrustMRR 驗證大方向
- 自己的頁面與付費測試驗證最後轉換

---

## 7. 治理層

### E1. SOP
- skill-download-vetting-sop
- fast gate criteria
- review architecture

### E2. 權限治理
- `PERMISSIONS.md`
- 最小權限
- default-deny egress

### E3. 升版治理
- diff gate
- 權限變更重審
- 依賴變更重審
- 網路行為變更重審

### E4. 稽核輸出
- L1 report
- L2 report
- deploy decision
- audit package

---

## 8. 自有層 vs 外部整合能力層

### 自有層
- SkillGate 品牌
- SOP
- 報告格式
- 模板包
- 電子書
- 決策框架
- Policy-as-Code
- Diff Gate
- 審查服務
- Guardian 產品規格

### 外部整合能力層
- vetting engine
- dependency risk module
- permission governance module
- sandbox engine
- network watcher
- scanning tools
- add-on threat intelligence

原則：
**安全過審 + 版本鎖定 + 定位誠實 = 可以納入 SkillGate 能力層。**

---

## 9. 當前優先事項
1. 完成純 SkillGate 版電子書
2. 定義模板包
3. 累積案例包
4. 跑高價值 skill 的安全檢查
5. 把外部規則來源產品化成 SkillGate 自有框架
