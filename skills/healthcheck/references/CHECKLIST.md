# CHECKLIST — healthcheck（我們自家版）

> 兩種模式：
> - **保守**：只檢查 + 提建議
> - **激進**：可提出修復計畫，預設 dry-run；你確認才 apply

## 0) 前置護欄（兩模式都必做）
- [ ] 開啟 trace + redaction
- [ ] 確認 PERMISSIONS.md 生效（default-deny egress；敏感路徑 deny）
- [ ] 所有變更行為：先列出「將改動項目」+ 風險 + 回滾方式

## 1) 系統健康
- [ ] 磁碟空間：低於門檻 → 提出清理建議（只針對可重建的 cache/log/transcripts）
- [ ] CPU/Memory：異常尖峰 → 建議調整並行度/重試
- [ ] 服務存活：gateway / agent 是否可用（health/ready 檢查）

## 2) OpenClaw 版本與設定漂移
- [ ] 版本：是否落後、是否有重大安全更新
- [ ] 設定漂移：與我們的 baseline 差異（輸出 diff）

## 2.1) SkillGate L1 加分檢查（選配）
- [ ] ClamAV（若環境有）：掃 skill 目錄
- [ ] YARA（若有規則庫）：掃可疑模式
- [ ] SBOM + Vuln DB（若工具可用）：產 SBOM + 漏洞掃描
  - 參考：`references/ADDON_CHECKS.md`

## 3) Secrets 與權限
- [ ] SecretRef/refs 是否可解析（啟用 surface 必須 fail-fast）
- [ ] 是否有不必要的 secrets 暴露（環境變數、log）

## 4) 工具最小權限
- [ ] agent 工具權限是否過大（exec/browser/nodes）
- [ ] 不必要能力提出縮權建議

## 5) Prompt-injection 防線
- [ ] 外部內容是否被當作指令使用的跡象（模板/工具鏈）
- [ ] 需要時：提出修補建議（隔離、明確指令階層、拒絕策略）

## 6) 激進模式（可選修復提案）
- [ ] 清理策略（dry-run）
- [ ] 設定修復（輸出前後 diff）
- [ ] 必要時服務重啟（先詢問你是否允許）
