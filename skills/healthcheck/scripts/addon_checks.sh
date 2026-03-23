#!/usr/bin/env bash
set -euo pipefail

# SkillGate L1 addon checks (best-effort): ClamAV, YARA, SBOM/Vuln
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

# 1) ClamAV
if command -v clamscan >/dev/null 2>&1; then
  report "## ClamAV"
  # --infected prints only infected files; do not fail the whole script on non-zero (clam uses 1 for infected)
  set +e
  clamscan -r --infected --no-summary "$TARGET_DIR" >"$OUT_DIR/clamav.txt" 2>&1
  code=$?
  set -e
  if [[ $code -eq 0 ]]; then
    report "ClamAV: OK (no hits)"
  elif [[ $code -eq 1 ]]; then
    report "ClamAV: HIT (see clamav.txt)"
  else
    report "ClamAV: ERROR (exit=$code; see clamav.txt)"
  fi
  report ""
else
  report "## ClamAV"
  report "ClamAV: SKIP (clamscan not installed)"
  report ""
fi

# 2) YARA
if command -v yara >/dev/null 2>&1; then
  report "## YARA"
  # Expect user to provide rules; default none.
  RULES_DIR="${YARA_RULES_DIR:-}"
  if [[ -n "$RULES_DIR" && -d "$RULES_DIR" ]]; then
    set +e
    yara -r "$RULES_DIR" "$TARGET_DIR" >"$OUT_DIR/yara.txt" 2>&1
    code=$?
    set -e
    if [[ $code -eq 0 ]]; then
      report "YARA: OK (no hits)"
    else
      report "YARA: HIT/ERROR (exit=$code; see yara.txt)"
    fi
  else
    report "YARA: SKIP (set YARA_RULES_DIR to a directory of .yar rules)"
  fi
  report ""
else
  report "## YARA"
  report "YARA: SKIP (yara not installed)"
  report ""
fi

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
