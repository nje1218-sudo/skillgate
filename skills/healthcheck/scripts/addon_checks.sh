#!/usr/bin/env bash
set -euo pipefail

# SkillGate L1 addon checks: ClamAV, YARA, SBOM/Vuln
# Exit codes:
#   0 = all tools clean (or skipped)
#   1 = ClamAV or YARA hit detected
# Usage:
#   ./addon_checks.sh <target_dir> <out_dir>

TARGET_DIR="${1:?target_dir required}"
OUT_DIR="${2:?out_dir required}"

mkdir -p "$OUT_DIR"

report() {
  printf "%s\n" "$*" | tee -a "$OUT_DIR/addon_checks.log" >/dev/null
}

report "# SkillGate L1 Addon Checks"
report "Target: $TARGET_DIR"
report "Time: $(date -u +%FT%TZ)"
report ""

HIT=0

# 1) ClamAV
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

# 2) YARA
report "## YARA"
if command -v yara >/dev/null 2>&1; then
  RULES_DIR="${YARA_RULES_DIR:-}"
  if [[ -n "$RULES_DIR" && -d "$RULES_DIR" ]]; then
    set +e
    yara -r "$RULES_DIR" "$TARGET_DIR" >"$OUT_DIR/yara.txt" 2>&1
    yara_exit=$?
    set -e
    if [[ $yara_exit -eq 0 ]]; then
      report "YARA: OK (no hits)"
    else
      report "YARA: HIT — rule matched (exit=$yara_exit; see yara.txt)"
      HIT=1
    fi
  else
    report "YARA: SKIP (set YARA_RULES_DIR to a directory of .yar rules)"
  fi
else
  report "YARA: SKIP (yara not installed)"
fi
report ""

# 3) SBOM + Vuln DB
report "## SBOM/Vuln"
if command -v syft >/dev/null 2>&1; then
  syft "$TARGET_DIR" -o json >"$OUT_DIR/sbom.syft.json" 2>/dev/null || true
  report "SBOM: generated (sbom.syft.json)"
else
  report "SBOM: SKIP (syft not installed)"
fi

if command -v grype >/dev/null 2>&1; then
  grype "$TARGET_DIR" -o json >"$OUT_DIR/vuln.grype.json" 2>/dev/null || true
  report "Vuln scan: generated (vuln.grype.json)"
elif command -v osv-scanner >/dev/null 2>&1; then
  osv-scanner --format=json --recursive "$TARGET_DIR" >"$OUT_DIR/vuln.osv.json" 2>/dev/null || true
  report "Vuln scan: generated (vuln.osv.json)"
else
  report "Vuln scan: SKIP (grype/osv-scanner not installed)"
fi

report ""
report "Done."

if [[ $HIT -eq 1 ]]; then
  echo "❌ addon_checks: malware/YARA hit detected — see $OUT_DIR/addon_checks.log"
  exit 1
fi
