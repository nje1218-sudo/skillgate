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
SECURECLAW_SCRIPTS="$(cd "$ROOT_DIR/../../secureclaw/skill/scripts" 2>/dev/null && pwd)" || SECURECLAW_SCRIPTS=""

mkdir -p "$OUT_DIR"

# ── Step 0: Canonicalise path + symlink escape detection ──────────────────────
# realpath resolves all symlinks and .. components in the caller-supplied path.
# Without this, a crafted path like "skills/../../../etc" bypasses scope checks.
TARGET_DIR="$(realpath "$TARGET_DIR")"

{
  echo "## Realpath + Symlink Escape Check"
  echo "Canonical target: $TARGET_DIR"
  echo
} >> "$OUT_DIR/l1_findings.md"

symlink_escapes=0
while IFS= read -r -d '' link; do
  resolved="$(readlink -f "$link" 2>/dev/null || true)"
  # Block if the resolved target is outside the skill directory
  if [[ -n "$resolved" ]] && [[ "$resolved" != "$TARGET_DIR"* ]]; then
    echo "  🔴 SYMLINK ESCAPE: $link -> $resolved" >> "$OUT_DIR/l1_findings.md"
    symlink_escapes=$((symlink_escapes + 1))
  fi
done < <(find "$TARGET_DIR" -type l -print0 2>/dev/null)

if [[ $symlink_escapes -gt 0 ]]; then
  echo "SYMLINK RESULT: BLOCKED — $symlink_escapes symlink(s) escape skill directory" \
    >> "$OUT_DIR/l1_findings.md"
  symlink_label="BLOCKED"
else
  echo "SYMLINK RESULT: OK" >> "$OUT_DIR/l1_findings.md"
  symlink_label="OK"
fi

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

# 3b) Dependency vulnerability check (OSV + malicious package list)
dep_exit=0
{
  echo "## Dependency Vulnerability Check (OSV)";
  echo "Target: $TARGET_DIR";
  echo;
} >> "$OUT_DIR/l1_findings.md"

set +e
python3 "$SECURECLAW_SCRIPTS/check-dependencies.py" "$TARGET_DIR" \
  >>"$OUT_DIR/l1_findings.md" 2>&1
dep_exit=$?
set -e

if [[ $dep_exit -eq 0 ]]; then
  echo "DEP RESULT: OK" >>"$OUT_DIR/l1_findings.md"
  dep_label="OK"
elif [[ $dep_exit -eq 1 ]]; then
  echo "DEP RESULT: BLOCKED — critical CVE or malicious package detected" >>"$OUT_DIR/l1_findings.md"
  dep_label="BLOCKED"
else
  echo "DEP RESULT: WARN — high/medium CVEs found" >>"$OUT_DIR/l1_findings.md"
  dep_label="WARN"
fi

{
  echo "- dep_check exit: $dep_exit (0=ok, 1=blocked, 2=warn)"
  echo "- dep_check result: $dep_label"
  echo
} >> "$OUT_DIR/decision.md"

# 4) Semgrep — semantic static analysis (catches obfuscated attacks regex misses)
semgrep_exit=0
if command -v semgrep >/dev/null 2>&1; then
  {
    echo "## Semgrep Semantic Analysis";
    echo "Target: $TARGET_DIR";
    echo;
  } >> "$OUT_DIR/l1_findings.md"

  set +e
  semgrep scan \
    --config p/security-audit \
    --config p/python \
    --config p/javascript \
    --json \
    --quiet \
    "$TARGET_DIR" >"$OUT_DIR/semgrep.json" 2>/dev/null
  semgrep_exit=$?
  set -e

  if [[ -s "$OUT_DIR/semgrep.json" ]]; then
    error_count=$(python3 -c "
import json, sys
try:
    d = json.load(open('$OUT_DIR/semgrep.json'))
    errors = [r for r in d.get('results', []) if r.get('extra', {}).get('severity') in ('ERROR', 'WARNING')]
    print(len(errors))
except Exception:
    print(0)
" 2>/dev/null || echo 0)

    if [[ "$error_count" -gt 0 ]]; then
      echo "SEMGREP RESULT: WARN — $error_count finding(s) (see semgrep.json)" >>"$OUT_DIR/l1_findings.md"
      semgrep_label="WARN"
      [[ $semgrep_exit -eq 0 ]] && semgrep_exit=2
    else
      echo "SEMGREP RESULT: OK" >>"$OUT_DIR/l1_findings.md"
      semgrep_label="OK"
    fi
  else
    echo "SEMGREP RESULT: OK" >>"$OUT_DIR/l1_findings.md"
    semgrep_label="OK"
  fi
else
  semgrep_label="SKIP"
fi

{
  echo "- semgrep exit: $semgrep_exit (0=ok, 2=warn)"
  echo "- semgrep result: $semgrep_label"
  echo
} >> "$OUT_DIR/decision.md"

# 5) IOC check (C2 servers, malicious names, infostealer targets)
ioc_exit=0
if [[ -n "$SECURECLAW_SCRIPTS" ]] && command -v python3 >/dev/null 2>&1; then
  {
    echo "## Supply Chain IOC Check";
    echo "Target: $TARGET_DIR";
    echo;
  } >> "$OUT_DIR/l1_findings.md"

  set +e
  python3 "$SECURECLAW_SCRIPTS/check-ioc.py" "$TARGET_DIR" "$SKILL_NAME" \
    >>"$OUT_DIR/l1_findings.md" 2>&1
  ioc_exit=$?
  set -e

  if [[ $ioc_exit -eq 0 ]]; then
    echo "IOC RESULT: OK" >>"$OUT_DIR/l1_findings.md"
    ioc_label="OK"
  elif [[ $ioc_exit -eq 1 ]]; then
    echo "IOC RESULT: BLOCKED — IOC match found" >>"$OUT_DIR/l1_findings.md"
    ioc_label="BLOCKED"
  else
    echo "IOC RESULT: WARN — suspicious pattern found" >>"$OUT_DIR/l1_findings.md"
    ioc_label="WARN"
  fi
else
  ioc_label="SKIP"
fi

# Append IOC signal to decision.md
{
  echo "- ioc_check exit: $ioc_exit (0=ok, 1=blocked, 2=warn)"
  echo "- ioc_check result: $ioc_label"
  echo
} >> "$OUT_DIR/decision.md"

# 5) L2 dynamic sandbox
l2_exit=0
if [[ -n "$SECURECLAW_SCRIPTS" ]] && command -v python3 >/dev/null 2>&1; then
  {
    echo "## L2 Dynamic Sandbox";
    echo "Target: $TARGET_DIR";
    echo;
  } >> "$OUT_DIR/l2_summary.md"

  set +e
  python3 "$SECURECLAW_SCRIPTS/l2-sandbox.py" "$TARGET_DIR" \
    --output "$OUT_DIR/l2_report.json" \
    >>"$OUT_DIR/l2_summary.md" 2>&1
  l2_exit=$?
  set -e

  if [[ $l2_exit -eq 0 ]]; then
    echo "L2 RESULT: OK" >>"$OUT_DIR/l2_summary.md"
    l2_label="OK"
  elif [[ $l2_exit -eq 1 ]]; then
    echo "L2 RESULT: BLOCKED — dangerous runtime behavior detected" >>"$OUT_DIR/l2_summary.md"
    l2_label="BLOCKED"
  else
    echo "L2 RESULT: WARN — suspicious runtime behavior" >>"$OUT_DIR/l2_summary.md"
    l2_label="WARN"
  fi
else
  l2_label="SKIP"
fi

{
  echo "- l2_sandbox exit: $l2_exit (0=ok, 1=blocked, 2=warn)"
  echo "- l2_sandbox result: $l2_label"
  echo
} >> "$OUT_DIR/decision.md"

# 6) Signature verification (Cosign / SLSA)
sig_exit=0
SIG_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify_signatures.sh"
if [[ -x "$SIG_SCRIPT" ]] && command -v cosign >/dev/null 2>&1; then
  {
    echo "## Signature Verification (Cosign/SLSA)";
    echo "Target: $TARGET_DIR";
    echo;
  } >> "$OUT_DIR/l1_findings.md"

  set +e
  "$SIG_SCRIPT" "$TARGET_DIR" "$OUT_DIR"
  sig_exit=$?
  set -e

  if [[ $sig_exit -eq 0 ]]; then
    sig_label="OK"
  else
    echo "SIG RESULT: BLOCKED — signature verification failed" >>"$OUT_DIR/l1_findings.md"
    sig_label="BLOCKED"
  fi
else
  sig_label="SKIP"
fi

{
  echo "- sig_verify exit: $sig_exit (0=ok, 1=blocked)"
  echo "- sig_verify result: $sig_label"
  echo
} >> "$OUT_DIR/decision.md"

# Block on symlink escape (must be checked before any file reads)
if [[ $symlink_escapes -gt 0 ]]; then
  echo "❌ SkillGate intake BLOCKED: symlink escape attempt in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

# Block on any critical finding
if [[ $policy_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: block-level policy violations in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

if [[ $dep_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: critical CVE or malicious package in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

if [[ $ioc_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: IOC match in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

if [[ $l2_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: dangerous runtime behavior in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

if [[ $sig_exit -eq 1 ]]; then
  echo "❌ SkillGate intake BLOCKED: signature verification failed in $SKILL_NAME. Report at $OUT_DIR"
  exit 1
fi

# 7) Smoke test — syntax-validate the skill entry point
smoke_exit=0
smoke_label="SKIP"
entry_point=""
for candidate in skill.py main.py index.py src/main.py app.py index.js src/index.js; do
  if [[ -f "$TARGET_DIR/$candidate" ]]; then
    entry_point="$TARGET_DIR/$candidate"
    break
  fi
done

{
  echo "## Smoke Test"
  echo "Entry point: ${entry_point:-none found}"
  echo
} >> "$OUT_DIR/l1_findings.md"

if [[ -n "$entry_point" ]]; then
  set +e
  case "$entry_point" in
    *.py)
      python3 -m py_compile "$entry_point" >> "$OUT_DIR/l1_findings.md" 2>&1
      smoke_exit=$?
      ;;
    *.js)
      node --check "$entry_point" >> "$OUT_DIR/l1_findings.md" 2>&1
      smoke_exit=$?
      ;;
  esac
  set -e

  if [[ $smoke_exit -eq 0 ]]; then
    echo "SMOKE RESULT: OK — entry point syntax valid" >> "$OUT_DIR/l1_findings.md"
    smoke_label="OK"
  else
    echo "SMOKE RESULT: WARN — entry point has syntax errors" >> "$OUT_DIR/l1_findings.md"
    smoke_label="WARN"
    smoke_exit=2
  fi
else
  echo "SMOKE RESULT: SKIP — no recognised entry point found" >> "$OUT_DIR/l1_findings.md"
fi

{
  echo "- smoke_test exit: $smoke_exit (0=ok, 2=warn)"
  echo "- smoke_test result: $smoke_label"
  echo
} >> "$OUT_DIR/decision.md"

# 8) Audit log — append one line per intake run
AUDIT_LOG="${ROOT_DIR}/../../reports/skillgate-audit.log"
mkdir -p "$(dirname "$AUDIT_LOG")"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OVERALL_RESULT="OK"
[[ $symlink_escapes -gt 0 || $policy_exit -eq 1 || $dep_exit -eq 1 || $ioc_exit -eq 1 || $l2_exit -eq 1 || $sig_exit -eq 1 ]] && OVERALL_RESULT="BLOCKED"
[[ $policy_exit -eq 2 || $dep_exit -eq 2 || $semgrep_exit -eq 2 || $ioc_exit -eq 2 || $l2_exit -eq 2 || $smoke_exit -eq 2 ]] && \
  [[ "$OVERALL_RESULT" != "BLOCKED" ]] && OVERALL_RESULT="WARN"

echo "${TIMESTAMP}  skill=${SKILL_NAME}  version=${VERSION}  result=${OVERALL_RESULT}  symlink=${symlink_label}  policy=${policy_label}  dep=${dep_label}  semgrep=${semgrep_label}  ioc=${ioc_label}  l2=${l2_label}  sig=${sig_label}  smoke=${smoke_label}  report=${OUT_DIR}" \
  >> "$AUDIT_LOG"

# Write approval record (only if overall result is OK or WARN)
if [[ "$OVERALL_RESULT" != "BLOCKED" ]]; then
  cat > "$OUT_DIR/APPROVED" <<APEOF
skill:       $SKILL_NAME
version:     $VERSION
approved_at: $TIMESTAMP
approved_by: SkillGate-auto
result:      $OVERALL_RESULT
symlink:     $symlink_label
policy:      $policy_label
dep:         $dep_label
semgrep:     $semgrep_label
ioc:         $ioc_label
l2:          $l2_label
sig:         $sig_label
smoke:       $smoke_label
canonical_path: $TARGET_DIR
APEOF
fi

echo "✅ SkillGate intake complete: result=${OVERALL_RESULT}  report=${OUT_DIR}"

# 9) Generate PERMISSIONS.md + report.md + report.json
POLICY_FILE="${ROOT_DIR}/configs/policy.yaml"
REPORTS_DIR="${ROOT_DIR}/../../reports"
REPORT_SCRIPT="${ROOT_DIR}/scripts/generate_report.py"

if [[ -f "$REPORT_SCRIPT" ]]; then
  set +e
  python3 "$REPORT_SCRIPT" \
    "$SKILL_NAME" "$VERSION" "$OUT_DIR" \
    --policy  "$POLICY_FILE" \
    --reports-dir "$REPORTS_DIR"
  report_gen_exit=$?
  set -e

  if [[ $report_gen_exit -eq 0 ]]; then
    echo "📄 Reports: ${REPORTS_DIR}/${SKILL_NAME}/"
  else
    echo "  WARN: report generation failed (exit=$report_gen_exit)" >&2
  fi
fi