# SkillGate 三層審查架構

## 核心定位
SkillGate 不只是「審得嚴」，而是：

- **先快速把 80% 明顯風險篩掉**
- **再把 20% 真正危險的抓去深審**

這是 SkillGate 的核心賣點之一：
**方便、效率、安全，不用讓使用者等到天荒地老。**

---

## Layer 1 — Fast Gate（秒到分鐘級）

### 目標
對大多數 skill 做第一層快速風險分流。

### 適用對象
- 一般 skill
- 一次下載很多 skill 的批次場景
- 先做低成本風險篩選

### 檢查內容
- 來源 / repo / 維護者 / 版本鎖定
- install / startup scripts
- `postinstall` / `preinstall`
- `curl` / `wget` / `webhook` / `exec` / `eval`
- 明顯外連
- 權限面粗分
- 依賴風險快掃
- 惡意特徵關鍵字快掃

### 輸出結果
- `Low risk`
- `Needs review`
- `Block`

### 商業價值
- 可支援大量 skill 快速分流
- 能縮短等待時間
- 讓 SkillGate 更容易被市場接受

---

## Layer 2 — Deep Gate（分鐘到小時級）

### 目標
把真正高風險、會碰核心能力的 skill 做深度驗證。

### 適用對象
- Fast Gate 未通過但也未明顯惡意
- 會碰 secrets / 外連 / exec / memory / runtime hooks 的 skill

### 檢查內容
- L2 sandbox / runtime behavior check
- 讀寫路徑
- 外連行為
- 權限越界
- prompt / lifecycle hooks
- report generation

### 輸出結果
- `Deploy`
- `Deploy w/ Monitor`
- `Block`

### 商業價值
- 保護 production
- 提供可稽核報告
- 把安全流程產品化

---

## Layer 3 — Batch Mode（大量下載模式）

### 目標
當使用者一次想裝很多 skill 時，不要每個都進人工深審。

### 流程
先跑全部 skill 的 Fast Gate，再分桶：

#### A 桶：可直接放行候選
- 低風險
- 工具型
- 不碰核心行為

#### B 桶：需要 Deep Gate
- 有外連
- 有 exec
- 有較大權限
- 有行為型風險

#### C 桶：直接 Block
- 明顯惡意
- 高風險模式明顯
- 來源不清
- 版本不鎖

### 商業價值
- 支援真實市場使用情境
- 不會因為太慢被嫌棄
- 讓 SkillGate 兼顧效率與安全

---

## 一句話版
SkillGate 的設計不是「每個技能都慢慢審」，而是：
**先快速把 80% 明顯風險篩掉，再把 20% 真正危險的抓去深審。**
