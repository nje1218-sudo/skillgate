#!/usr/bin/env bash
set -euo pipefail

# SkillGate one-click intake (MVP)
# Purpose: generate a complete intake report pack with policy checks and addon checks.
#
# Usage:
#   ./skillgate_intake.sh <target_dir> <skill_name> <version> <out_dir>
#
# Notes:
# - This does NOT run L2 SecureClaw; it prepares the pack and highlights what to run.

TARGET_DIR="${1:?target_dir required}"
SKILL_NAME="${2:?skill_name required}"
VERSION="${3:?version required}"
OUT_DIR="${4:?out_dir required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$OUT_DIR"

# 1) Create base pack
(
  cd "$ROOT_DIR"
  ./scripts/generate_intake_report_pack.sh "$SKILL_NAME" "$VERSION" "$OUT_DIR"
)

# 2) Policy check
{
  echo "## Policy-as-Code";
  echo "Policy: references/policy.yaml";
  echo "Target: $TARGET_DIR";
  echo;
} >> "$OUT_DIR/l1_findings.md"

set +e
python3 "$ROOT_DIR/scripts/policy_check.py" "$TARGET_DIR" >>"$OUT_DIR/l1_findings.md" 2>&1
policy_exit=$?
set -e

if [[ $policy_exit -eq 0 ]]; then
  echo "POLICY RESULT: OK" >>"$OUT_DIR/l1_findings.md"
  policy_label="OK"
elif [[ $policy_exit -eq 1 ]]; then
  echo "POLICY RESULT: BLOCKED — block-level violations found" >>"$OUT_DIR/l1_findings.md"
  policy_label="BLOCKED"
else
  echo "POLICY RESULT: WARN — review required before admission" >>"$OUT_DIR/l1_findings.md"
  policy_label="WARN"
fi

# 3) Guidance for L1/L2 steps
cat >>"$OUT_DIR/decision.md" <<EOF
# Decision (Draft)

- This pack is prepared by SkillGate one-click intake.
- Next required steps for real admission:
  1) L1: run skill-vetting scan (per sops/skill-download-vetting-sop.md)
  2) L2: run SecureClaw sandbox simulation (per SOP)

## Preliminary signal
- policy_check exit: $policy_exit (0=ok, 1=blocked, 2=warn)
- policy_check result: $policy_label

EOF

if [[ $policy_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: block-level policy violations in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

echo "OK: SkillGate intake generated at $OUT_DIR"