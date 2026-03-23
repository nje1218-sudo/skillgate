#!/usr/bin/env bash
set -euo pipefail

# SkillGate Diff Gate (stub)
# Compare two versions of a skill folder and flag:
# - dependency changes
# - PERMISSIONS.md changes
# - new external URLs
#
# Usage:
#   ./diff_gate.sh <old_dir> <new_dir>

OLD_DIR="${1:?old_dir required}"
NEW_DIR="${2:?new_dir required}"

fail=0

echo "== PERMISSIONS diff =="
if [[ -f "$OLD_DIR/references/PERMISSIONS.md" && -f "$NEW_DIR/references/PERMISSIONS.md" ]]; then
  diff -u "$OLD_DIR/references/PERMISSIONS.md" "$NEW_DIR/references/PERMISSIONS.md" || fail=1
else
  echo "WARN: PERMISSIONS.md missing in one side" >&2
  fail=1
fi

echo

echo "== Dependency diff (best-effort) =="
for f in package.json package-lock.json pnpm-lock.yaml yarn.lock requirements.txt poetry.lock; do
  if [[ -f "$OLD_DIR/$f" || -f "$NEW_DIR/$f" ]]; then
    diff -u "$OLD_DIR/$f" "$NEW_DIR/$f" || fail=1
  fi
done

echo

echo "== New URL/egress indicators (best-effort) =="
old_urls=$(grep -RhoE 'https?://[^"\s)]+' "$OLD_DIR" 2>/dev/null | sort -u || true)
new_urls=$(grep -RhoE 'https?://[^"\s)]+' "$NEW_DIR" 2>/dev/null | sort -u || true)
comm -13 <(printf "%s\n" "$old_urls") <(printf "%s\n" "$new_urls") | sed 's/^/- NEW: /' || true

if [[ $fail -ne 0 ]]; then
  echo "\nDIFF_GATE: changes detected or missing required files" >&2
  exit 2
fi

echo "\nDIFF_GATE: no critical diffs detected"
