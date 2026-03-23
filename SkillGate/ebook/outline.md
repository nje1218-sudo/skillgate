# 《OpenClaw / Agent Skills 安全上線手冊》

## 0. 書籍定位
- **定位**：給正在使用或準備使用 OpenClaw / Agent Skills 的開發者、AI builder、個人工作室與小團隊的 Skill 安全上線實戰手冊。
- **核心承諾**：幫讀者用一套可執行 SOP，降低 skill / plugin 下載、權限放大、供應鏈污染與升版風險。
- **目標結果**：讀者看完後，能自己建立最小可用的 Skill 安全門禁，而不是直接拿 production 裸奔測 skill。
- **產品角色**：這本不是終局產品；它是 SkillGate 的前端驗證產品、名單收集器、信任建立器。

---

## 1. 目標讀者
### 核心讀者
1. 會下載 OpenClaw / agent skills / plugins 的 builder
2. 想把 AI agent 用在真實工作流、接案、商業流程的人
3. 擔心資料外洩、權限失控、供應鏈污染的人
4. 想建立可重複 skill 審查流程的小團隊 / 個人工作室

### 次要讀者
1. AI automation 顧問
2. 想賣 OpenClaw setup / maintenance 服務的人
3. 想建立 AI agent 安全上線流程的人

### 不適合的讀者
1. 只想看 AI 趨勢，不想動手的人
2. 完全不碰技術與設定的人
3. 期待一本到位講完所有 runtime / reliability 問題的人

---

## 2. 核心賣點
1. **不是 OpenClaw 入門大全，是 Skill 安全上線門禁手冊**
2. **不是空泛安全觀念，是 SOP + checklist + template + decision logic**
3. **直接對應真實痛點**：
   - 來源不明
   - 隱藏外連 / webhook / exec
   - 權限開太大
   - install hooks / supply chain 風險
   - 升版後風險漂移
4. **可直接導流到 SkillGate**：
   - 模板包
   - 審查服務
   - 報告包 / Diff Gate
   - SkillGate Guardian waitlist

---

## 3. 建議書名候選
### 主推
- **《OpenClaw / Agent Skills 安全上線手冊》**

### 備選
- 《OpenClaw Skills 安全上線與審查實戰》
- 《AI Agent 不裸奔：Skill 安全落地 SOP》
- 《The OpenClaw SkillGate Playbook》

### 副標候選
- 從 L1/L2 vetting、權限治理到升版 gate 的實戰 SOP
- 用最小權限、安全門禁與報告包，讓 AI agent 能真的安全上線

---

## 4. 章節架構

## Chapter 1｜為什麼 Agent Skills 需要安全門禁
### 目標
建立痛點與危機感，讓讀者知道 skill 安裝不是小事，而是供應鏈問題。

### 內容
- 多數人只學怎麼裝 skill，卻沒學怎麼審
- skill / plugin 為什麼等於把執行能力交給外部供應鏈
- 市場上多數內容的缺口：
  - 教安裝
  - 不教安全入庫
  - 不教升版重審
- SkillGate 想解決的就是這個缺口

### 交付物
- 「你目前是不是在裸奔裝 skill」自測表

---

## Chapter 2｜Skill 下載前的風險地圖
### 目標
讓讀者先看懂風險面，再進 SOP。

### 內容
- typosquatting
- install hooks / postinstall
- 遠端腳本執行
- 權限過大
- prompt injection / 指令污染
- 外連與資料外傳
- 升版 drift / 行為漂移

### 交付物
- Skill 風險地圖
- Fast Gate 初版風險分類表

---

## Chapter 3｜SkillGate L1：原始碼與依賴審查
### 目標
建立第一層快審能力。

### 內容
- 來源、版本鎖定、維護者可信度
- 惡意特徵快掃：
  - `curl | bash`
  - `wget | sh`
  - webhook / 裸 IP
  - base64 decode-and-run
  - `postinstall` / `preinstall`
- dependency risk：
  - typosquat
  - publisher
  - install hooks
  - transitive dependency
  - license
- Fast Gate 輸出：
  - `Low risk`
  - `Needs review`
  - `Block`

### 交付物
- L1 checklist
- dependency risk 模板
- Fast Gate 結論模板

---

## Chapter 4｜SkillGate L2：Sandbox 行為驗證
### 目標
對高風險 / 不確定 skill 做第二層深審。

### 內容
- 什麼情況要進 L2
- sandbox / runtime behavior check
- 讀寫路徑
- 網路行為
- child process / exec
- 權限越界與執行隔離
- Deep Gate 結果：
  - `Deploy`
  - `Deploy w/ Monitor`
  - `Block`

### 交付物
- L2 checklist
- sandbox profile 範本
- Deep Gate 結論模板

---

## Chapter 5｜權限宣告與最小權限設計
### 目標
把「權限治理」從抽象概念變成可執行規則。

### 內容
- OpenClaw 四大權限怎麼看
- 危險組合判定：
  - `network + fileRead`
  - `network + shell`
  - `shell + fileWrite`
- 權限風險如何翻譯成人能懂的語言
- 最小權限設計
- `PERMISSIONS.md` 該怎麼寫

### 交付物
- `PERMISSIONS.md` 範本
- 權限風險矩陣

---

## Chapter 6｜報告包、Policy-as-Code 與 Diff Gate
### 目標
讓 skill 審查變成可治理、可稽核、可升版追蹤的流程。

### 內容
- 入庫報告包要包含什麼
- Policy-as-Code 怎麼幫忙擋風險
- 升版重審為什麼必要
- 權限 diff / 依賴 diff / 外連 diff
- 不是第一次過審就永遠安全

### 交付物
- 入庫報告模板
- 升版重審模板
- Diff Gate 範例

---

## Chapter 7｜從手冊到產品：如何把這套流程變成 SkillGate
### 目標
把書自然導到產品，不讓它停在 PDF。

### 內容
- SkillGate 的定位
- 為什麼安全不是終點，而是營收系統的底層保障
- SkillGate 的商業層：
  - 電子書
  - 模板包
  - 審查服務
  - 報告包 / Diff Gate
  - SkillGate Guardian
- 買完這本後下一步是什麼

### 交付物
- SkillGate 產品階梯圖
- 讀者下一步 CTA

---

## 5. 附錄設計
### Appendix A｜L1 檢查清單
### Appendix B｜L2 檢查清單
### Appendix C｜`PERMISSIONS.md` 範本
### Appendix D｜入庫報告模板
### Appendix E｜升版重審模板
### Appendix F｜常見高風險特徵速查表

---

## 6. 每章固定格式
每章建議固定這 5 段：
1. 這章要解決什麼問題
2. 典型錯誤
3. 正確做法
4. 直接可用模板 / checklist
5. 今天就能做的動作

---

## 7. 建議篇幅
- **總長**：7 章 + 6 個附錄
- **主文**：12,000–18,000 字（MVP 版）
- **附錄 / 模板**：可另外拆成 bonus pack

### 版本策略
- **MVP 版**：12,000–15,000 字，快速上市驗證
- **完整版**：18,000–25,000 字，再補案例、圖表與模板包細節

---

## 8. 商業設計
### 定價建議
- MVP 電子書：**US$19**
- 電子書 + 模板包：**US$29–49**
- 電子書 + 模板包 + 審查入口：**US$99+**

### Upsell 路徑
1. 電子書
2. 模板包 / 報告包
3. SkillGate 審查服務
4. SkillGate Guardian / Reliability Layer

---

## 9. 首頁一句話定位
- **讓 OpenClaw / Agent Skills 真正安全上線的實戰手冊。**
- **不是教你裝更多 skill，而是教你別把 production 交給來路不明的供應鏈。**

---

## 10. 下一步寫作順序
### 最先寫的 3 章
1. Chapter 3｜SkillGate L1：原始碼與依賴審查
2. Chapter 5｜權限宣告與最小權限設計
3. Chapter 6｜報告包、Policy-as-Code 與 Diff Gate

### 原因
- 最接近 SkillGate 本體
- 最有差異化
- 最能形成可賣 MVP

---

## 11. 寫作原則
- 不講空話
- 不寫 AI 趨勢作文
- 每章都要有可直接採用的模板 / SOP
- 用市場缺口 + 案例 + 決策邏輯去支撐說服力
- 每章都要能導向下一個可賣產品
