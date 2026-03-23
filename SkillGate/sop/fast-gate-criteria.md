# SkillGate Fast Gate — 初版審查標準

## 目標
Fast Gate 的任務不是證明一個 skill 100% 安全，而是：

- 在秒到分鐘級內
- 先把 **80% 明顯風險** 篩出來
- 把剩下真正危險或不明的 20% 丟進 Deep Gate

---

## 一、輸出分類
Fast Gate 只輸出 3 種結果：

- `Low risk`
- `Needs review`
- `Block`

---

## 二、必檢項目

### 1. 來源與版本
- repo / maintainer 是否清楚
- 是否能鎖定 tag / commit
- 是否使用漂移來源（`main` / `master` / `latest`）

#### 直接 Block
- 來源不明
- 無法鎖版本
- 維護者 / 發布來源明顯可疑

---

### 2. 安裝與啟動腳本
檢查：
- `postinstall`
- `preinstall`
- 安裝後立即下載執行
- shell 包裝腳本

#### 高風險特徵
- `curl | bash`
- `wget | sh`
- `powershell -enc`
- `bash -c` 動態拼接命令
- 下載後 `chmod +x` 再執行

#### 預設判定
- 明顯遠端腳本執行 → `Block`
- 安裝腳本複雜且不透明 → `Needs review`

---

### 3. 可疑命令與執行能力
檢查關鍵字：
- `curl`
- `wget`
- `nc` / `netcat`
- `ssh`
- `exec(`
- `eval(`
- `Function(`
- `spawn(`
- `child_process`
- `subprocess`

#### 判定原則
- 單純出現不等於惡意
- 但若與：
  - 遠端下載
  - 可疑網域
  - base64
  - 背景執行
  - secrets 路徑
  同時出現，風險升高

---

### 4. 外連與 webhook
檢查：
- `http://`
- `https://`
- webhook URLs
- bare IP
- 短網址
- 不明網域

#### 直接 Block
- 裸 IP 下載 payload
- 明顯 C2 / webhook exfiltration 路徑
- 不明 domain + 遠端執行鏈

#### Needs review
- 合理 SaaS endpoint 但權限用途不明
- 多個第三方外連且未說明用途

---

### 5. 混淆與隱藏執行
檢查：
- base64 blobs
- hex blobs
- 明顯混淆字串拼接
- 壓縮後再 decode-and-run

#### 高風險特徵
- base64 decode 後出現 `curl` / `wget` / `ssh` / `exec`
- 以圖片、副檔名偽裝 payload
- 以 innocuous file / config 偽裝命令

#### 預設判定
- decode-and-run → `Block` 或至少 `Needs review`

---

### 6. 敏感路徑與憑證意圖
檢查是否碰：
- `~/.ssh/`
- `~/.aws/`
- wallet files
- env secrets
- `secrets/`
- OpenClaw memory/system files（如 `SOUL.md`, `MEMORY.md`）

#### 直接 Block
- 明顯嘗試讀憑證並外傳
- 明顯修改持久化 prompt / memory 來植入惡意行為

---

### 7. Prompt Injection / 指令污染跡象
檢查：
- skill 文件中是否出現試圖覆寫 agent 規則的內容
- 是否鼓勵忽略安全邏輯
- 是否要求自動下載、執行、外傳資料

#### Needs review / Block
- 若內容明顯試圖影響系統 prompt、記憶或安全規則 → 至少 `Needs review`，嚴重則 `Block`

---

## 三、Fast Gate 初版高風險特徵庫
以下特徵出現時，直接提高風險等級：

1. `curl | bash` / `wget | sh`
2. base64 decode-and-run
3. 裸 IP payload download
4. `chmod +x` + 背景執行
5. webhook / exfil endpoint
6. 讀取 `~/.ssh`, `~/.aws`, wallet, `secrets/`
7. prompt / memory persistence tampering
8. 忽略 SSL (`curl -k`) 或異常 redirect 鏈 (`-L`) 搭配下載執行
9. 短網址 / 可疑 domain / password-protected ZIP
10. 遠端下載 + 本地執行 + 權限提升鏈

---

## 四、Fast Gate 的產品價值
Fast Gate 的價值不是「完美」，而是：

- 大量 skill 可先快速分流
- 使用者不用等很久
- 能把低風險工具型 skill 快速放行
- 把高風險 skill 導入 Deep Gate

一句話：
**先快篩，再深審。這就是 SkillGate 兼顧市場速度與安全性的關鍵。**

---

## 五、後續擴充方向
- 納入更多惡意樣本規則
- 連接 YARA / ClamAV / IOC feed
- 建立可機器判斷的 policy rules
- 納入 OpenClaw / agent 生態特有風險模式
