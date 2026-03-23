# SkillGate 市場對比表 + 優勢 / 缺口分析

## 目的
這份文件用來回答三件事：

1. 市場上已經有哪些相近東西
2. SkillGate 現在真正的優勢是什麼
3. 我們還缺哪些東西，才能更像一個可賣產品

---

## 一、我們不是空白市場
目前市場上已經存在幾種相近的內容/產品：

### 1. 泛 OpenClaw handbook / playbook
**特徵**
- 教你怎麼用 OpenClaw / Clawdbot
- 偏部署、自動化、入門教學
- 強調 setup、workflow、效率

**市場訊號**
- 已經有 OpenClaw / Clawdbot automation 類 ebook / playbook
- 有人願意為「怎麼部署、怎麼跑 agent」付錢

**和 SkillGate 的差異**
- 這類多半教「怎麼開始」
- SkillGate 教「怎麼安全地開始、怎麼審、怎麼留報告、怎麼做 gate」

---

### 2. security / hardening 文章
**特徵**
- security architecture
- cheat sheet
- hardening guide
- prompt injection / least privilege / audit 建議

**市場訊號**
- 安全議題確實有人關心
- 但這類內容多數停在文章與指南，未必是完整產品

**和 SkillGate 的差異**
- 這類內容偏知識傳遞
- SkillGate 可以做成 SOP + checklist + 模板 + 報告包

---

### 3. watchdog / health-check / doctor 類 skill
**特徵**
- health monitoring
- watchdog
- self-healing
- auto-restart
- diagnostics

**市場訊號**
- runtime pain 很真
- OpenClaw 生態對 health/doctor/watchdog 有真需求

**和 SkillGate 的差異**
- 這類主要解 runtime / reliability
- SkillGate 第一階段不主打 runtime 修復，而是 skill / plugin 安全門禁與治理
- runtime 內容可成為 SkillGate Guardian / 第二本書 / 第二產品

---

### 4. skills 清單 / 市集 / awesome list
**特徵**
- 教你裝哪些 skill
- 推薦熱門 skill
- 彙整技能市場資源

**市場訊號**
- 使用者確實需要 skill discovery
- 社群很喜歡「必裝 skill」這種內容

**和 SkillGate 的差異**
- 多數人只教裝什麼
- 很少人系統化教：
  - 怎麼安全下載
  - 怎麼審 skill
  - 怎麼做 L1 / L2
  - 怎麼做升版重審
  - 怎麼做報告包 / Diff Gate

---

## 二、外部市場證據（補充）
除了 OpenClaw 社群內容本身，我們也可用更廣的市場訊號來輔助驗證：

### TrustMRR / 已驗證收入網站
**用途**
- 看是否有人真的為 AI automation / agent / SaaS / workflow 工具付費
- 幫助判斷大方向是否有商業價值

**能驗證什麼**
- 這類市場有人買單
- 類似題材的收入模型存在
- AI automation / sales / SEO / deployment 等方向有真 MRR

**不能直接驗證什麼**
- SkillGate 這個切角一定會賣
- 電子書一定會有人買
- 哪個文案一定會轉換

**結論**
- TrustMRR 適合當成「市場驗證來源之一」
- 不適合取代自己的 landing page / preorder / 小額付費測試

---

## 三、SkillGate 目前真正的優勢

### 優勢 1：切角夠窄，而且夠痛
SkillGate 現在不是做泛 AI handbook，而是聚焦在：
- skill / plugin 安全門禁
- L1 / L2 vetting
- 權限宣告
- 報告包
- Policy-as-Code
- Diff Gate

這個切角比泛 OpenClaw 教學更尖，也更有產品感。

---

### 優勢 2：可延伸成真正的產品資產
目前可直接延伸的自有產品資產是：
- 模板包
- 審查服務
- SkillGate Guardian
- 報告包 / 升版 Gate

> 注意：**外部候選 skill / plugin 不算我們的產品延伸。**
> 例如外部的 vetting 類 skill，在沒完成審查、沒正式納入前，不應視為自家產品能力。

這讓 SkillGate 不只是一本書，而是一條產品路徑。

---

### 優勢 3：我們有真實踩坑經驗
雖然第一本書不主打 runtime reliability，但我們已經踩過：
- memory/provider 問題
- gateway timeout
- session noise
- heartbeat/交付追蹤問題

這些踩坑讓我們做 SOP 時比較不像抄 docs，可信度更高。

---

### 優勢 4：能做成「可執行資產」而不是純知識
SkillGate 天生適合做：
- checklist
- `PERMISSIONS.md`
- L1/L2 report template
- 入庫報告包
- 升版重審模板
- Policy-as-Code 規則

這些東西比單純文章更接近可賣產品。

---

## 四、SkillGate 目前缺的東西

### 缺口 1：明確市場證據頁
現在有判斷，但還缺一份更完整的：
- 競品/替代品地圖
- 相關 ebook / article / skill / service 清單
- 他們在賣什麼
- 我們刻意不賣什麼

這份文件是第一步，但後面還要持續補案例與連結。

---

### 缺口 2：案例包
第一本如果只有原則，會偏虛。
至少需要補：
- 1 個 skill 下載審查案例
- 1 個 L1 → L2 → decision 範例
- 1 個升版 diff gate mini case

案例會大幅提升說服力與產品感。

---

### 缺口 3：模板包內容定義
現在知道要賣模板包，但還不夠具體：
- 會包含哪些檔案
- 哪些會免費 preview
- 哪些是付費內容
- 模板包與審查服務怎麼銜接

---

### 缺口 4：對外市場語言
目前我們比較強的是內部產品規劃語言，但還缺：
- landing page 文案
- 對外 pain points
- 對外 promise
- CTA 設計

如果沒有這層，會變成內部覺得很強，對外卻賣不動。

---

## 五、SkillGate 現階段應該怎麼定位

### 不要這樣講
- OpenClaw 全能手冊
- 最全面的 agent 指南
- 幫你搞定所有 AI agent 問題

這些都太大，也太空。

### 要這樣講
SkillGate 是：
- **OpenClaw / Agent Skills 的安全上線門禁系統**
- **把 skill 下載、審查、升版與報告做成 SOP 的產品化框架**
- **讓 builder 不用拿 production 裸奔測 skill 的方法論 + 工具資產**

---

## 六、第一本電子書最應該補的 4 個元素

### 1. 市場現況對比（一小節）
重點不是寫研究報告，而是讓讀者知道：
- 多數內容在教裝 skill
- 很少內容在教安全入庫與升版治理
- 這就是 SkillGate 的市場缺口

### 2. 一個完整案例
- 某個 skill 候選
- L1 看什麼
- L2 看什麼
- 最後為什麼 Block / Deploy w/ Monitor / Deploy

### 3. 升版風險 mini case
讓讀者知道：
- 審過一次不等於永遠安全
- 升版是另一個坑

### 4. 更產品化的 CTA
書末與章節結尾要引導讀者：
- 拿模板
- 送審
- 預約 review
- 加入 SkillGate Guardian waitlist

---

## 七、我們現在不該做什麼
- 不該把第一本書寫成 runtime reliability 大雜燴
- 不該把外部候選 skill 直接算成自家產品能力
- 不該只寫觀念，不留模板 / 報告 / 交付物
- 不該把電子書當終局產品

---

## 八、結論
### 現在最值得押的方向
**第一本書聚焦 SkillGate Core：**
- skill / plugin 安全門禁
- L1 / L2 vetting
- 權限宣告
- 報告包
- Policy-as-Code
- Diff Gate
- 產品化路線

### 後續延伸
- 模板包
- 審查服務
- SkillGate Guardian
- 報告包 / 升版 Gate

### 市場判斷一句話
市場上有相似內容，但還沒有很漂亮地把：
**skill 安全門禁 + SOP + 報告包 + 產品化路線**
打成一套。這就是 SkillGate 最有機會切進去的位置。
