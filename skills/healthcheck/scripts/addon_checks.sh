#!/usr/bin/env bash
set -euo pipefail

# SkillGate L1 Addon Checks: ClamAV, YARA, TruffleHog, SBOM/Vuln
# Exit codes:
#   0 = all tools clean (or skipped)
#   1 = ClamAV / YARA / TruffleHog hit detected
# Usage:
#   ./addon_checks.sh <target_dir> <out_dir>

TARGET_DIR="${1:?target_dir required}"
OUT_DIR="${2:?out_dir required}"

mkdir -p "$OUT_DIR"

# Default YARA rules: bundled supply-chain.yar (next to this script's secureclaw parent)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILTIN_RULES="$(cd "$SCRIPT_DIR/../../secureclaw/skill/rules" 2>/dev/null && pwd)" || BUILTIN_RULES=""

report() {
  printf "%s\n" "$*" | tee -a "$OUT_DIR/addon_checks.log" >/dev/null
}

report "# SkillGate L1 Addon Checks"
report "Target: $TARGET_DIR"
report "Time: $(date -u +%FT%TZ)"
report ""

HIT=0

# ── 1) ClamAV ─────────────────────────────────────────────────────────────
report "## ClamAV"
if command -v clamscan >/dev/null 2>&1; then
  set +e
  clamscan -r --infected --no-summary "$TARGET_DIR" >"$OUT_DIR/clamav.txt" 2>&1
  clamav_exit=$?
  set -e
  if [[ $clamav_exit -eq 0 ]]; then
    report "ClamAV: OK (no hits)"
  elif [[ $clamav_exit -eq 1 ]]; then
    report "ClamAV: HIT — malware detected (see clamav.txt)"
    HIT=1
  else
    report "ClamAV: ERROR (exit=$clamav_exit; see clamav.txt)"
  fi
else
  report "ClamAV: SKIP (clamscan not installed)"
fi
report ""

# ── 2) YARA (bundled supply-chain rules + optional custom rules) ────────────
report "## YARA"
if command -v yara >/dev/null 2>&1; then
  # Prefer explicit YARA_RULES_DIR; fall back to bundled rules
  RULES_DIR="${YARA_RULES_DIR:-$BUILTIN_RULES}"
  if [[ -n "$RULES_DIR" && -d "$RULES_DIR" ]]; then
    set +e
    yara -r "$RULES_DIR" "$TARGET_DIR" >"$OUT_DIR/yara.txt" 2>&1
    yara_exit=$?
    set -e
    if [[ $yara_exit -eq 0 ]]; then
      report "YARA: OK (no hits)"
    else
      report "YARA: HIT — supply-chain rule matched (see yara.txt)"
      HIT=1
    fi
  else
    report "YARA: SKIP (no rules directory found)"
  fi
else
  report "YARA: SKIP (yara not installed)"
fi
report ""

# ── 3) TruffleHog — verified secret/credential scanning ───────────────────
report "## TruffleHog"
if command -v trufflehog >/dev/null 2>&1; then
  set +e
  trufflehog filesystem "$TARGET_DIR" \
    --only-verified \
    --json \
    >"$OUT_DIR/trufflehog.json" 2>/dev/null
  trufflehog_exit=$?
  set -e

  if [[ -s "$OUT_DIR/trufflehog.json" ]]; then
    count=$(grep -c '"DetectorName"' "$OUT_DIR/trufflehog.json" 2>/dev/null || echo 0)
    report "TruffleHog: HIT — $count verified credential(s) found (see trufflehog.json)"
    HIT=1
  elif [[ $trufflehog_exit -eq 0 ]]; then
    report "TruffleHog: OK (no verified credentials found)"
  else
    report "TruffleHog: ERROR (exit=$trufflehog_exit)"
  fi
elif command -v gitleaks >/dev/null 2>&1; then
  # Gitleaks as fallback (no live verification, but fast)
  set +e
  gitleaks detect --no-git --source "$TARGET_DIR" \
    --report-format json --report-path "$OUT_DIR/gitleaks.json" \
    --quiet 2>/dev/null
  gitleaks_exit=$?
  set -e
  if [[ $gitleaks_exit -eq 0 ]]; then
    report "Gitleaks: OK (no secrets found)"
  elif [[ $gitleaks_exit -eq 1 ]]; then
    report "Gitleaks: HIT — secrets detected (see gitleaks.json)"
    HIT=1
  else
    report "Gitleaks: ERROR (exit=$gitleaks_exit)"
  fi
else
  report "TruffleHog/Gitleaks: SKIP (neither installed — run: brew install trufflehog)"
fi
report ""

# ── 4) SBOM + Vulnerability DB ────────────────────────────────────────────
report "## SBOM/Vuln"
if command -v syft >/dev/null 2>&1; then
  syft "$TARGET_DIR" -o cyclonedx-json >"$OUT_DIR/sbom.cyclonedx.json" 2>/dev/null || true
  report "SBOM: generated (sbom.cyclonedx.json)"
else
  report "SBOM: SKIP (syft not installed)"
fi

if command -v grype >/dev/null 2>&1; then
  grype "$TARGET_DIR" -o json >"$OUT_DIR/vuln.grype.json" 2>/dev/null || true
  report "Vuln scan: generated via Grype (vuln.grype.json)"
elif command -v osv-scanner >/dev/null 2>&1; then
  osv-scanner scan source --format json --recursive "$TARGET_DIR" \
    >"$OUT_DIR/vuln.osv.json" 2>/dev/null || true
  report "Vuln scan: generated via OSV-Scanner (vuln.osv.json)"
else
  report "Vuln scan: SKIP (grype/osv-scanner not installed)"
fi
report ""

report "Done."

if [[ $HIT -eq 1 ]]; then
  echo "❌ addon_checks: hit detected (ClamAV/YARA/TruffleHog) — see $OUT_DIR/addon_checks.log"
  exit 1
fi
