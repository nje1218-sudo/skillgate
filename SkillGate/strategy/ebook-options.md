# Ebook Options for SkillGate

## 採用方案（主推）
### 方案 A｜安全 + 營運交界
- **主題**：`《OpenClaw / Agent Skills 安全上線手冊》`
- **定位**：安全上線、skill vetting、權限控管、incident recovery、doctor/watchdog 設計
- **目的**：作為 SkillGate 的前端驗證產品，導流到模板包、審查服務、Guardian
- **狀態**：**目前主推 / 已開始執行**

---

## 保留方案（暫不主推）

### 方案 B｜營運導向
- **題目方向**：`《讓 OpenClaw 穩定運作的自癒營運手冊》`
- **核心內容**：
  - gateway timeout 排查
  - memory/provider 故障處理
  - doctor / watchdog 設計
  - heartbeat / cron / incident log
  - 真實故障案例與修復流程
- **優點**：
  - 更容易打到已在用 OpenClaw 的人
  - 比較偏 reliability / ops，跟 Guardian 產品線很順
- **缺點**：
  - 安全門禁角度較弱
  - 對 SkillGate brand 的第一印象不如方案 A 完整
- **適合何時做**：
  - 方案 A 賣出後，作為第二本延伸書
  - 或後續拆成 Guardian 專題 handbook
- **狀態**：保留候選

---

### 方案 C｜變現導向
- **題目方向**：`《用 OpenClaw + Skills 建立可賣服務的實戰 SOP》`
- **核心內容**：
  - 如何把 agent 能力包成服務
  - 技能安全門禁
  - reliability layer
  - 報價與交付模板
  - 從內容/工具到服務的變現設計
- **優點**：
  - 錢味最重
  - 最容易直接連到顧問服務、產品化、接案 SOP
- **缺點**：
  - 範圍太大，最容易寫成大便山
  - 對第一本書來說，焦點容易失控
  - 如果案例不足，會顯得太早賣夢
- **適合何時做**：
  - 等方案 A/B 驗證完市場後，再升級成更高價產品
  - 或拆成 workshop / course / 顧問方案
- **狀態**：保留候選

---

## 決策理由
目前先做方案 A，而不是 B/C，原因：

1. 最貼近 SkillGate 現在已有資產
   - SOP
   - vetting
   - policy
   - reports
   - doctor/guardian 構想

2. 最容易用低成本做出第一版可賣內容

3. 最能自然導流到後續產品：
   - 模板包
   - 審查服務
   - SkillGate Guardian

4. 不會太虛，也不會太大

---

## 後續產品順序建議
1. **方案 A**：安全上線手冊（先做）
2. **方案 B**：自癒營運手冊（第二本或 Guardian 專題）
3. **方案 C**：可賣服務 SOP（高價版 / 顧問導向）
