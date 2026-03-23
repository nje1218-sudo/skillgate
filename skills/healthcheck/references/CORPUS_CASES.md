# SkillGate 案例包（公開 mock）

> 目的：讓買家一看就懂 SkillGate 的價值，並可用於銷售頁截圖。

## Case A — Clean Pass（Deploy）
- 情境：純本地檢查、無外連、無 install hooks。
- 預期：policy=OK；addon checks 多為 SKIP/OK。

## Case B — Webhook Exfil（Block）
- 情境：skill 內藏 webhook/URL，並嘗試用 curl/wget 對外送資料。
- 預期：policy=BLOCK（network_exec_keywords/webhook_or_url）。

## Case C — Secrets Overreach（Block）
- 情境：skill 嘗試讀取 `secrets/` 或 `~/.ssh/`。
- 預期：policy=BLOCK（secrets_path_reference）。

## 交付物
每個 case 應提供：
- 目標資料夾（mock skill dir）
- 用 `skillgate_intake.sh` 產出的 report pack
- 3 張銷售頁用截圖（l1_findings / decision / addon_checks）
