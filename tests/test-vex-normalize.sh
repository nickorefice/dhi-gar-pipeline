#!/usr/bin/env bash
#
# Regression tests for scripts/lib/vex-normalize.jq.
#
# This file exists because of a bug that produced no error and no wrong number --
# only a missing effect. The pipeline extracted DHI's VEX, unwrapped it, passed it
# to Trivy and Grype with --vex, and reported success. Neither scanner applied a
# single statement, because DHI names Debian SOURCE packages
# (pkg:deb/debian/glibc@...) while the scanners match the BINARY package they found
# (pkg:deb/debian/libc6@...). Measured on dhi-node:26-debian13:
#
#   original VEX -> Trivy 12 findings, Grype 6, grype ignoredMatches 0
#   normalised   -> Trivy  0 findings, Grype 0
#
# All 12 were CVEs the vendor had already declared not_affected. "0 suppressed"
# reads identically whether VEX worked with nothing to do or was silently ignored,
# which is why this needs a test rather than an eyeball.
#
#   ./tests/test-vex-normalize.sh

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURES="$TESTS_DIR/fixtures"

pass=0; fail=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

OUT="$(jq -f "$ROOT/scripts/lib/vex-normalize.jq" \
        --argjson packages "$(cat "$FIXTURES/scanner-packages.json")" \
        "$FIXTURES/vex-source-package.json")"

echo "== mapping source packages to the binaries scanners report"
check "3 statements remapped"          "3" "$(jq -r '.mappings | length' <<<"$OUT")"
check "glibc -> libc6"                '["libc6"]' \
  "$(jq -c '.mappings[] | select(.vulnerability=="CVE-2026-5435") | .to' <<<"$OUT")"
check "one source -> many binaries"   '["libssl3t64","openssl-provider-legacy"]' \
  "$(jq -c '.mappings[] | select(.vulnerability=="CVE-2010-0928") | .to' <<<"$OUT")"
check "epoch handled (zlib -> zlib1g)" '["zlib1g"]' \
  "$(jq -c '.mappings[] | select(.vulnerability=="CVE-2026-27171") | .to' <<<"$OUT")"

echo "== a version mismatch is reported, never guessed"
check "1 statement unmatched"         "1" "$(jq -r '.unmatched | length' <<<"$OUT")"
check "the unmatched one is the bogus version" "CVE-9999-0001" \
  "$(jq -r '.unmatched[0].vulnerability' <<<"$OUT")"
check "unmatched statement gained no products" "1" \
  "$(jq -r '.vex.statements[] | select(.vulnerability.name=="CVE-9999-0001") | .products | length' <<<"$OUT")"

echo "== the normalised document is usable by a scanner"
check "scanner PURL present for glibc statement" "true" \
  "$(jq -r '[.vex.statements[] | select(.vulnerability.name=="CVE-2026-5435") | .products[]["@id"]]
            | any(test("libc6"))' <<<"$OUT")"
check "original products retained (additive, not replaced)" "true" \
  "$(jq -r '[.vex.statements[] | select(.vulnerability.name=="CVE-2026-5435") | .products[]["@id"]]
            | any(test("/glibc@"))' <<<"$OUT")"
check "unrelated package never mapped in" "false" \
  "$(jq -r '[.vex.statements[].products[]["@id"]] | any(test("nodejs"))' <<<"$OUT")"

# The assessment itself must survive untouched. Normalisation is a translation of
# identifiers; if it can alter a status or a justification it is inventing vendor
# claims, which is worse than applying no VEX at all.
echo "== the vendor's assessment is copied verbatim"
check "statement count unchanged"     "4" "$(jq -r '.vex.statements | length' <<<"$OUT")"
check "every status still not_affected" "true" \
  "$(jq -r '[.vex.statements[].status] | all(. == "not_affected")' <<<"$OUT")"
check "justification preserved"       "vulnerable_code_cannot_be_controlled_by_adversary" \
  "$(jq -r '.vex.statements[] | select(.vulnerability.name=="CVE-2026-5435") | .justification' <<<"$OUT")"
check "author preserved"              "Docker Hardened Images <dhi@docker.com>" \
  "$(jq -r '.vex.author' <<<"$OUT")"
check "no CVE invented or dropped"    "CVE-2010-0928,CVE-2026-27171,CVE-2026-5435,CVE-9999-0001" \
  "$(jq -r '[.vex.statements[].vulnerability.name] | sort | join(",")' <<<"$OUT")"

echo "== degenerate inputs"
check "empty package inventory -> nothing mapped, nothing lost" "0|4" \
  "$(jq -f "$ROOT/scripts/lib/vex-normalize.jq" --argjson packages '[]' \
       "$FIXTURES/vex-source-package.json" \
     | jq -r '"\(.mappings|length)|\(.vex.statements|length)"')"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
