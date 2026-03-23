#!/bin/bash
# SecureClaw — Skill Supply Chain Scanner
# Developed by Adversa AI — Agentic AI Security and Red Teaming Pioneers
# https://adversa.ai
# Usage: bash scan-skills.sh              (scan all installed skills)
#        bash scan-skills.sh /path/to/skill (scan specific skill)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPENCLAW_DIR=""
for dir in "$HOME/.openclaw" "$HOME/.moltbot" "$HOME/.clawdbot" "$HOME/clawd"; do
  [ -d "$dir" ] && OPENCLAW_DIR="$dir" && break
done
[ -z "$OPENCLAW_DIR" ] && echo "❌ No OpenClaw found" && exit 1

SCAN_DIR="${1:-$OPENCLAW_DIR/skills}"
[ ! -d "$SCAN_DIR" ] && echo "✅ Nothing to scan at $SCAN_DIR" && exit 0

echo "🔒 SecureClaw — Skill Supply Chain Scan"
echo "========================================"
SAFE=0; SUS=0; T=0; SKIPPED=0; CRITICAL=0

scan_dir() {
  local d="$1" n="$2"
  T=$((T+1)); local ISSUES=""

  local HAS_CRITICAL=0

  # Remote code execution — flexible whitespace, pipe to shell (critical)
  grep -rlE '(curl|wget)\s*\|\s*(sh|bash|python[23]?|perl|ruby|node)\b' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 Remote code execution (pipe-to-shell)\n" && HAS_CRITICAL=1 || true

  # Remote code execution — cross-line pipe (curl/wget ... newline ... | sh)
  grep -rlzE '(curl|wget)[^\x00]{0,200}\|\s*(sh|bash|python[23]?|perl|ruby|node)\b' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 Remote code execution (cross-line pipe)\n" && HAS_CRITICAL=1 || true

  # Equivalent remote execution tools (critical)
  grep -rlE '\bsocat\b.+EXEC|\bnc\s+-[ce]\s|\bbusybox\s+(sh|ash|wget|curl)\b' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 Remote code execution (equivalent tool)\n" && HAS_CRITICAL=1 || true

  # One-liner execution via scripting tools (critical)
  grep -rlE '\bperl\s+-e\s|\bruby\s+-e\s|\bnode\s+-e\s|\bpython[23]?\s+-c\s' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 Remote code execution (one-liner)\n" && HAS_CRITICAL=1 || true

  # Dynamic execution (critical)
  grep -rlE '\beval\s*\(|\bexec\s*\(|\bFunction\s*\(|subprocess\.(call|run|Popen).*shell.*True|os\.(system|popen)\(' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 Dynamic code execution\n" && HAS_CRITICAL=1 || true

  # Obfuscation (warning)
  grep -rlE '\batob\s*\(|\bbtoa\s*\(|String\.fromCharCode|\\\\x[0-9a-fA-F]{2}' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🟠 Obfuscated code\n" || true

  # Credential access (warning)
  grep -rlE 'process\.env|\.env\b|api_key|apiKey|API_KEY' "$d" 2>/dev/null \
    | grep -v node_modules | head -1 | grep -q . && ISSUES="${ISSUES}  🟠 Credential access\n" || true

  # Config modification (warning)
  grep -rlE 'SOUL\.md|IDENTITY\.md|TOOLS\.md|openclaw\.json' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🟠 Config/identity modification\n" || true

  # ClawHavoc patterns (critical)
  grep -rlE 'osascript.*display|xattr.*quarantine|ClickFix|webhook\.site' "$d" 2>/dev/null \
    | head -1 | grep -q . && ISSUES="${ISSUES}  🔴 ClawHavoc campaign pattern\n" && HAS_CRITICAL=1 || true

  # ClawHavoc name patterns (critical)
  case "$n" in
    *solana-wallet*|*phantom-tracker*|*polymarket-*|*better-polymarket*|*auto-updater*|*clawhub[0-9]*|*clawhubb*|*cllawhub*)
      ISSUES="${ISSUES}  🔴 Name matches ClawHavoc blocklist\n"; HAS_CRITICAL=1 ;;
  esac

  # Dangerous commands (config-driven: block / require_approval / warn)
  if command -v python3 >/dev/null 2>&1; then
    local dc_out dc_exit
    dc_out=$(python3 "$SCRIPT_DIR/check-dangerous-commands.py" "$d" 2>/dev/null)
    dc_exit=$?
    if [[ $dc_exit -eq 1 ]]; then
      ISSUES="${ISSUES}  🔴 Dangerous commands (block)\n$(echo "$dc_out" | sed 's/^/    /')\n"
      HAS_CRITICAL=1
    elif [[ $dc_exit -eq 2 ]]; then
      ISSUES="${ISSUES}  🟠 Dangerous commands (require approval/warn)\n$(echo "$dc_out" | sed 's/^/    /')\n"
    fi

    # Supply chain IOC check (C2 servers, malicious names, infostealer targets)
    local ioc_out ioc_exit
    ioc_out=$(python3 "$SCRIPT_DIR/check-ioc.py" "$d" "$n" 2>/dev/null)
    ioc_exit=$?
    if [[ $ioc_exit -eq 1 ]]; then
      ISSUES="${ISSUES}  🔴 IOC match (block)\n$(echo "$ioc_out" | sed 's/^/    /')\n"
      HAS_CRITICAL=1
    elif [[ $ioc_exit -eq 2 ]]; then
      ISSUES="${ISSUES}  🟠 IOC suspicious pattern\n$(echo "$ioc_out" | sed 's/^/    /')\n"
    fi
  fi

  if [ -z "$ISSUES" ]; then
    echo "✅ $n — clean"; SAFE=$((SAFE+1))
  else
    echo "⚠️  $n:"; echo -e "$ISSUES"; SUS=$((SUS+1))
    [ "$HAS_CRITICAL" -eq 1 ] && CRITICAL=$((CRITICAL+1))
  fi
}

for skill_dir in "$SCAN_DIR"/*/; do
  [ ! -d "$skill_dir" ] && continue
  # Skip ourselves — our configs contain the detection patterns we're scanning for
  [ "$(basename "$skill_dir")" = "secureclaw" ] && SKIPPED=$((SKIPPED+1)) && continue
  scan_dir "$skill_dir" "$(basename "$skill_dir")"
done

# If scanning a single directory (not a skills parent) — only trigger if no subdirs were found at all
if [ $T -eq 0 ] && [ $SKIPPED -eq 0 ] && [ -d "$SCAN_DIR" ]; then
  scan_dir "$SCAN_DIR" "$(basename "$SCAN_DIR")"
fi

echo ""
echo "📊 Scanned $T: $SAFE clean, $SUS suspicious ($CRITICAL critical)"
if [ $SUS -gt 0 ]; then
  echo "⚠️  Review suspicious skills. Remove any you didn't install yourself."
fi
if [ $CRITICAL -gt 0 ]; then
  echo "❌ $CRITICAL critical issue(s) found — block installation."
  exit 1
fi
