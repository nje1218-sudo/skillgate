#!/usr/bin/env bash
# verify_signatures.sh — Cosign & SLSA signature verification for skill archives
#
# Usage:
#   ./verify_signatures.sh <target_dir> [out_dir]
#
# Exit codes:
#   0 = all present signatures verified (skipped = ok)
#   1 = at least one signature FAILED verification
set -euo pipefail

TARGET_DIR="${1:?target_dir required}"
OUT_DIR="${2:-}"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

verify_cosign() {
  local archive="$1"
  local bundle="${archive}.cosign.bundle"
  local sig="${archive}.sig"

  if [ -f "$bundle" ]; then
    if cosign verify-blob \
      --bundle "$bundle" \
      --certificate-identity-regexp ".*" \
      --certificate-oidc-issuer-regexp ".*" \
      "$archive" 2>/dev/null; then
      RESULTS+=("COSIGN PASS: $archive")
      PASS=$((PASS+1))
    else
      RESULTS+=("COSIGN FAIL: $archive")
      FAIL=$((FAIL+1))
    fi
  elif [ -f "$sig" ]; then
    if cosign verify-blob \
      --signature "$sig" \
      --certificate-identity-regexp ".*" \
      --certificate-oidc-issuer-regexp ".*" \
      "$archive" 2>/dev/null; then
      RESULTS+=("COSIGN PASS: $archive")
      PASS=$((PASS+1))
    else
      RESULTS+=("COSIGN FAIL: $archive")
      FAIL=$((FAIL+1))
    fi
  else
    RESULTS+=("COSIGN SKIP: $archive (no signature found)")
    SKIP=$((SKIP+1))
  fi
}

verify_slsa() {
  local archive="$1"
  local provenance="${archive}.intoto.jsonl"

  if [ ! -f "$provenance" ]; then
    RESULTS+=("SLSA SKIP: $archive (no provenance)")
    return
  fi

  if ! command -v slsa-verifier &>/dev/null; then
    RESULTS+=("SLSA SKIP: $archive (slsa-verifier not installed)")
    return
  fi

  if slsa-verifier verify-artifact \
    --provenance-path "$provenance" \
    --source-uri "github.com/$(git remote get-url origin 2>/dev/null | sed 's|.*github.com[:/]||;s|\.git$||')" \
    "$archive" 2>/dev/null; then
    RESULTS+=("SLSA PASS: $archive")
    PASS=$((PASS+1))
  else
    RESULTS+=("SLSA FAIL: $archive")
    FAIL=$((FAIL+1))
  fi
}

# Scan for archives
while IFS= read -r archive; do
  verify_cosign "$archive"
  verify_slsa "$archive"
done < <(find "$TARGET_DIR" -name "*.tar.gz" -o -name "*.zip" 2>/dev/null | sort)

# Print results
echo "## Signature Verification Results"
echo ""
for r in "${RESULTS[@]}"; do
  echo "- $r"
done
echo ""
echo "PASS=$PASS  SKIP=$SKIP  FAIL=$FAIL"

# Write to out_dir if given
if [[ -n "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
  {
    echo "## Signature Verification"
    echo ""
    for r in "${RESULTS[@]}"; do
      echo "- $r"
    done
    echo ""
    echo "PASS=$PASS  SKIP=$SKIP  FAIL=$FAIL"
  } >> "$OUT_DIR/l1_findings.md"
fi

if [[ $FAIL -gt 0 ]]; then
  echo "❌ Signature verification BLOCKED: $FAIL archive(s) failed." >&2
  exit 1
fi

exit 0
