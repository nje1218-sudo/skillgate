#!/usr/bin/env bash
set -euo pipefail

# SkillGate Intake Report Pack generator (stub)
# Creates a folder with the standard artifacts described in SOP section 7.
#
# Usage:
#   ./generate_intake_report_pack.sh <skill_name> <version> <out_dir>

SKILL_NAME="${1:?skill_name}"
VERSION="${2:?version}"
OUT_DIR="${3:?out_dir}"

mkdir -p "$OUT_DIR"

cat >"$OUT_DIR/README.md" <<EOF
# SkillGate 入庫報告包

- Skill: $SKILL_NAME
- Version: $VERSION

## Contents
- l1_findings.md
- l2_summary.md
- PERMISSIONS.md (or manifest)
- allowlist.md (if applicable)
- addon_checks.log (optional)
- clamav.txt / yara.txt / sbom*.json / vuln*.json (optional)
- decision.md (Deploy / Deploy w/ Monitor / Block)
EOF

touch "$OUT_DIR/l1_findings.md" "$OUT_DIR/l2_summary.md" "$OUT_DIR/decision.md"

# Copy permissions if caller places it next to script execution cwd
if [[ -f "references/PERMISSIONS.md" ]]; then
  cp "references/PERMISSIONS.md" "$OUT_DIR/PERMISSIONS.md"
else
  echo "WARN: references/PERMISSIONS.md not found; add it to the pack manually" >&2
fi

# Run addon checks — surface exit code to caller
if [[ -x "scripts/addon_checks.sh" ]]; then
  echo "Running addon checks..." >&2
  set +e
  scripts/addon_checks.sh . "$OUT_DIR"
  addon_exit=$?
  set -e
  if [[ $addon_exit -ne 0 ]]; then
    echo "WARN: addon_checks reported findings (exit=$addon_exit) — see $OUT_DIR/addon_checks.log" >&2
  fi
fi

echo "OK: created report pack at $OUT_DIR"
