# SkillGate L1 能力拆解表

## 目的
這份文件用來把 SkillGate L1（Fast Gate）拆清楚：

- 外部模組目前提供什麼
- SkillGate 要放大什麼
- SkillGate 要補什麼缺口
- 最終要輸出成什麼產品能力

核心原則：
**SkillGate 不是照抄外部模組，而是把外部能力產品化。**

---

## L1 的產品任務
L1 = **Fast Gate**

目標不是證明 skill 100% 安全，而是：
- 快速把明顯風險篩掉
- 給使用者可決策的結論
- 決定哪些 skill 進 L2 深審

L1 輸出只做三種：
- `Low risk`
- `Needs review`
- `Block`

---

# 一、Vetting / Static Scan 基底

## 外部模組目前提供什麼
### `skill-vetter` / `skill-auditor` 類
- skill 來源與描述檢查
- 危險指令快掃
- 可疑內容檢查
- typosquatting 初步判斷
- prompt injection / social engineering red flags

## SkillGate 要放大什麼
- 標準化成 **Fast Gate 規則集**
- 建立固定紅旗特徵庫：
  - `curl | bash`
  - `wget | sh`
  - `postinstall`
  - `preinstall`
  - webhook / 裸 IP
  - base64 decode-and-run
  - credential path references
- 做成 rule-based scoring

## SkillGate 要補什麼
- 統一 verdict engine
- 版本漂移 / 升版重審邏輯
- 規則命中後的標準輸出格式
- 可機器判斷的 policy rules

## 最終輸出
- `static-risk-score`
- `matched-red-flags`
- `verdict: Low risk / Needs review / Block`
- `why-this-was-flagged`（人話版）

---

# 二、Dependency Risk Layer

## 外部模組目前提供什麼
### `dependency-auditor`
- package legitimacy
- typosquatting
- publisher identity
- install hooks
- transitive dependency 風險
- vuln DB 參考
- license compatibility

## SkillGate 要放大什麼
- 把 dependency 檢查變成 **標準化 dependency risk score**
- 把 install hooks / transitive deps / typosquat 直接映射到 Fast Gate 結果
- 接進 report template / diff gate / policy gate

## SkillGate 要補什麼
- 規則可機器化
- 依賴 diff compare
- 風險分級標準
- 與 SBOM / vuln DB / advisories 整合

## 最終輸出
- `dependency-risk-score`
- `dependency-findings`
- `hook-risk`
- `supply-chain-status`
- `upgrade-review-required: yes/no`

---

# 三、Permission Governance Layer

## 外部模組目前提供什麼
### `permission-auditor`
- fileRead / fileWrite / network / shell 解釋
- 危險權限組合判定
- 最小權限建議
- plain-language 風險說明

## SkillGate 要放大什麼
- 權限風險矩陣
- permission fit scoring
- 最小權限建議模板
- 讓權限分析進入報告與 deploy 決策

## SkillGate 要補什麼
- policy enforcement 條件
- 風險分級
- 自動觸發 L2 的條件
- 升版時權限 diff 機制

## 最終輸出
- `permission-fit-score`
- `dangerous-combinations`
- `minimum-required-permissions`
- `governance-recommendation`

---

# 四、Network / Exfiltration Layer

## 外部模組目前提供什麼
### `network-watcher` / 類似模組
- endpoint 審查
- 外連風險說明
- exfiltration pattern 檢查
- declared vs undeclared network usage

## SkillGate 要放大什麼
- allowlist / denylist 結構
- 網路目的地分類
- 外連合理性評估
- network 權限與 fileRead/shell 的交叉風險

## SkillGate 要補什麼
- endpoint policy
- IOC / domain reputation / threat intel 接入
- network diff（升版時新增 endpoint）
- 更明確的 block 條件

## 最終輸出
- `network-risk-score`
- `declared-endpoints`
- `undeclared-network-flags`
- `exfiltration-risk`

---

# 五、L1 決策引擎（SkillGate 自有層）

## 外部模組目前提供什麼
- 各種局部審查觀點
- checklist / textual guidance
- 模組化規則來源

## SkillGate 要放大什麼
- 把分散模組整合成統一決策流
- 讓使用者不是看一堆 checklist，而是直接得到 verdict

## SkillGate 要補什麼
- **scoring engine**
- **verdict engine**
- **report schema**
- **block / review / allow policy**
- **batch mode 分桶邏輯**

## 最終輸出
```json
{
  "verdict": "Needs review",
  "riskScores": {
    "static": "high",
    "dependency": "medium",
    "permissions": "high",
    "network": "medium"
  },
  "reasons": [
    "postinstall hook present",
    "network + fileRead combination",
    "undeclared third-party endpoint"
  ],
  "nextStep": "Deep Gate"
}
```

---

# 六、L1 與 L2 的銜接

## L1 要回答的問題
- 這個 skill 有沒有明顯紅旗？
- 有沒有高風險權限組合？
- 有沒有 supply chain / install hook 問題？
- 有沒有需要進一步沙箱驗證？

## 什麼情況直接 Block
- 明顯惡意特徵
- 無法鎖版本
- 裸 IP payload / decode-and-run
- credential path + exfiltration pattern
- 高風險 install chain

## 什麼情況進 L2
- 有外連但理由不夠清楚
- 有 shell / runtime hooks
- 權限偏大但不確定是否惡意
- 有需要觀察實際行為的風險

---

# 七、SkillGate L1 的真正產品價值

SkillGate L1 賣的不是「我們也會掃描」。

賣的是：
1. **速度**：先快速把 80% 明顯風險篩掉
2. **決策**：不是只列 checklist，而是直接給 verdict
3. **治理**：有報告、有 diff、有升版邏輯
4. **可擴充**：外部模組可接進來，但 SkillGate 自己掌握規則與輸出

---

# 八、目前最值得優先產品化的三塊

## Priority 1 — Dependency Risk
因為最容易直接變成規則、分數、報告。

## Priority 2 — Permission Governance
因為最容易被使用者理解，也最能形成產品說服力。

## Priority 3 — Network / Exfiltration Risk
因為這是很多 skill 真正危險的地方，且能直接影響 Block / Review 決策。

---

# 九、一句話版
SkillGate L1 的任務不是叫使用者自己讀完一堆安全清單，
而是：
**把外部模組的觀點整合成一個能快速給出 verdict、能留下報告、能決定是否進 Deep Gate 的產品級 Fast Gate。**
