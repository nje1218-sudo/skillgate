# REPORT_TEMPLATE — healthcheck（我們自家版）

## 摘要
- 模式：保守 / 激進
- 結論：OK / Needs attention / Blocker
- 最高風險：<一句話>

## 系統健康
- Disk:
- CPU/Memory:
- Services health:

## OpenClaw 版本與設定
- 版本：
- 設定漂移：
- 建議：

## SkillGate L1 加分檢查（選配）
- ClamAV：OK / HIT / SKIP（證據/檔名）
- YARA：OK / HIT / SKIP（命中規則/檔名）
- SBOM/Vuln：OK / HIT / SKIP（高危清單）

## Secrets / 權限
- SecretRef 解析：
- 疑似洩漏：
- 建議：

## 工具最小權限
- 現況：
- 建議縮權：

## Prompt Injection 防線
- 觀察：
- 建議：

## 變更（若有）
- 變更清單（dry-run / applied）：
- Diff / 位置：
- 回滾方式：

## Trace / 稽核
- trace id / log path：
- redaction 規則：
