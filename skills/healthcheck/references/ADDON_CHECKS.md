# SkillGate L1 擴充：加分檢查（ClamAV / YARA / SBOM+Vuln DB）

> 定位：**額外加分檢查**（best-effort）。
> - 不取代：L1 `skill-vetting`、L2 SecureClaw sandbox。
> - 原則：在不增加外連/權限的前提下做「更像資安團隊會做的掃描」。

## 1) ClamAV（病毒碼）
- 目標：掃描 skill 目錄內的檔案，抓已知惡意樣本。
- 優點：對已知惡意檔（payload）很有效。
- 盲點：供應鏈木馬常不長得像傳統病毒（無法全靠它）。

## 2) YARA rules（規則庫）
- 目標：用 YARA 規則掃描可疑模式（混淆、loader、特定 family 特徵）。
- 優點：比病毒碼彈性，適合針對「你在意的攻擊型態」加規則。
- 盲點：規則需要維護；誤判要有處理流程。

## 3) SBOM + Vuln DB（依賴/漏洞）
- 目標：產 SBOM（依賴清單）+ 比對 CVE/OSV 等漏洞資料庫。
- 優點：把依賴鏈風險顯性化；升版 diff gate 也更有依據。
- 盲點：
  - 漏洞 ≠ 可利用；需要 severity/context 判讀。
  - 需要工具（如 syft/grype 或 osv-scanner）。

## 建議輸出（報告包要有）
- ClamAV：是否掃到命中（含檔名）
- YARA：命中規則/檔案
- SBOM/Vuln：
  - 依賴清單摘要
  - 高危漏洞清單（含 CVE/OSV id）

