# SkillGate L1 報告（2026-03-06）— 6 skills（staging）

範圍：`/home/node/.openclaw/workspace/skills_staging/*`
政策基準：`skills/healthcheck/references/DEFAULT_SKILLGATE_POLICY.md`

> L1 是靜態掃描／字串跡象；**不等於安全**。任何需要外連或執行程式的 skill，下一步應走 L2（SecureClaw sandbox，default-deny egress + allowlist）。

---

## 結論摘要（建議）

| Skill (slug) | 風險級別 | 建議 | 需要 allowlist / 注意事項 |
|---|---:|---|---|
| `openclaw-skill-vetter` | 中 | **Deploy w/ Monitor** | 需要 `curl`/`jq`；若用內建範例會外連 GitHub 等。嚴禁讀 `~/.ssh` / `~/.aws`（policy 已 deny）。 |
| `tavily-search` | 中 | **Deploy w/ Monitor** | 需要 `TAVILY_API_KEY`；外連 `api.tavily.com:443`（必列入 allowlist）。 |
| `self-improving` | 低 | Deploy | 純文字邊界/流程描述；目前未見外連或動態執行碼。 |
| `proactive-agent-lite` | 低 | Deploy | 目前未見外連或動態執行碼。 |
| `find-skills` | 低-中 | Deploy w/ Monitor | 指向 `skills.sh`（資訊/瀏覽）。若未來擴成自動下載，需重新審。 |
| `summarize` | 中 | **Deploy w/ Monitor** | 需要多種 provider API key（OpenAI/Anthropic/xAI/Google 等）；可能會抓 URL/YouTube（外連需控）。 |

---

## 證據（節錄）

### 1) `openclaw-skill-vetter`
- 偵測到 `curl` 使用（多處，含 GitHub API 範例）：
  - `skills_staging/openclaw-skill-vetter/SKILL.md:161` `curl -s "https://api.github.com/repos/OWNER/REPO" | ...`
  - `.../SKILL.md:169` `https://raw.githubusercontent.com/...`
- 偵測到敏感路徑（示例/紅旗案例文字）：
  - `.../SKILL.md:255` 範例包含 `$(cat ~/.ssh/id_rsa)`（此為「惡意示例」，但代表這 skill 內容會教你怎麼辨識這種外洩）
- 觀察：L1 命中的 `evil.com` / `~/.ssh` 都出現在「教學示例」而非可執行腳本；但**因為它會用 curl**，L2 建議仍要把 egress 鎖死，只允許你需要的網域。

**建議 allowlist（若要使用其檢查/範例）：**
- `api.github.com:443`
- `raw.githubusercontent.com:443`
- （可選）`api.weather.gov:443`

### 2) `tavily-search`
- 外連（程式碼中明確 fetch）：
  - `skills_staging/tavily-search/scripts/search.mjs:62` `fetch("https://api.tavily.com/search", ...)`
  - `skills_staging/tavily-search/scripts/extract.mjs:24` `fetch("https://api.tavily.com/extract", ...)`
- 需要環境變數：
  - `.../scripts/search.mjs:42` 讀 `process.env.TAVILY_API_KEY`

**建議 allowlist：**
- `api.tavily.com:443`

### 3) `summarize`
- 宣告多種 API keys（文件層級）：
  - `skills_staging/summarize/SKILL.md:23-26` `OPENAI_API_KEY / ANTHROPIC_API_KEY / XAI_API_KEY / GEMINI_API_KEY ...`
- 指向外部網站 / 影片：
  - `.../SKILL.md:17` `https://youtu.be/...`

**建議：**
- 走 L2 時必須把 egress 拆成：
  - LLM provider 端點（依你用哪家）
  - 內容抓取端點（如果它會抓 URL/YouTube）

### 4) `find-skills`
- 指向 `https://skills.sh/`（瀏覽/索引）：
  - `skills_staging/find-skills/SKILL.md:32`

### 5) `self-improving`
- 目前主要是流程/邊界文件，未見外連/動態執行碼。

### 6) `proactive-agent-lite`
- 目前未見外連/動態執行碼。

---

## L1 產物
- JSON 掃描原始輸出：`reports/skillgate/2026-03-06/L1-scan.json`

## 下一步（要你拍板）
1) 我建議對 **`tavily-search`**、**`summarize`**、**`openclaw-skill-vetter`** 走 L2 sandbox（因為涉及外連/keys）。
2) 你若要先用：我可以先把 **低風險 3 個**（`self-improving`, `proactive-agent-lite`, `find-skills`）搬進 `skills/` 啟用；其餘等 L2。
