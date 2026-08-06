#!/usr/bin/env bash
#
# Unit tests for scripts/lib/classify.jq -- the attestation classifier that the
# verify gate's pass/fail decision rests on.
#
# These run with no network and no cloud credentials, which is the point: the
# classifier is the piece most likely to be quietly wrong, and it should not
# take a live GAR round-trip to find out.
#
#   ./tests/test-classify.sh

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURES="$TESTS_DIR/fixtures"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"

pass=0; fail=0

check() { # check <name> <expected> <actual>
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

run() { classify_referrers "$FIXTURES/$1"; }

echo "== referrers-direct.json (artifactType convention)"
out="$(run referrers-direct.json)"
check "total descriptors"      "6"                        "$(jq -r '.total' <<<"$out")"
check "no missing groups"      "[]"                       "$(jq -c '.groupsMissing' <<<"$out")"
check "groups present"         '["provenance","sbom","vex"]' "$(jq -c '.groupsPresent' <<<"$out")"
check "unclassified count"     "1"                        "$(jq -r '.unclassified' <<<"$out")"
check "spdx classified"        "sbom-spdx"                "$(jq -r '.artifacts[0].class' <<<"$out")"
check "cyclonedx classified"   "sbom-cyclonedx"           "$(jq -r '.artifacts[1].class' <<<"$out")"
check "slsa via predicate"     "provenance-slsa"          "$(jq -r '.artifacts[2].class' <<<"$out")"
check "openvex classified"     "vex-openvex"              "$(jq -r '.artifacts[3].class' <<<"$out")"
check "cosign sig classified"  "signature-cosign"         "$(jq -r '.artifacts[4].class' <<<"$out")"
check "unknown -> unclassified" "unclassified"            "$(jq -r '.artifacts[5].class' <<<"$out")"
check "title annotation read"  "sbom.spdx.json"           "$(jq -r '.artifacts[0].title' <<<"$out")"

echo "== referrers-intoto.json (predicate-annotation convention)"
out="$(run referrers-intoto.json)"
check "no missing groups"      "[]"                       "$(jq -c '.groupsMissing' <<<"$out")"
check "spdx via predicate"     "sbom-spdx"                "$(jq -r '.artifacts[0].class' <<<"$out")"
check "slsa v0.2 prefix match" "provenance-slsa"          "$(jq -r '.artifacts[1].class' <<<"$out")"
check "openvex versioned ns"   "vex-openvex"              "$(jq -r '.artifacts[2].class' <<<"$out")"
check "vuln report classified" "vuln-report"              "$(jq -r '.artifacts[3].class' <<<"$out")"
# A generic Docker attestation manifest with no predicate annotation must fall
# through to the generic class, NOT be counted toward a required group -- it
# needs deep inspection (see 90-inspect-referrers.sh) before it means anything.
check "bare attestation manifest" "attestation-manifest-generic" "$(jq -r '.artifacts[4].class' <<<"$out")"
check "generic has no group"   "null"                     "$(jq -r '.artifacts[4].group' <<<"$out")"

echo "== referrers-missing-vex.json (gate must fail)"
out="$(run referrers-missing-vex.json)"
check "vex reported missing"   '["vex"]'                  "$(jq -c '.groupsMissing' <<<"$out")"
check "sbom+provenance ok"     '["provenance","sbom"]'    "$(jq -c '.groupsPresent' <<<"$out")"

echo "== referrers-empty.json (no attestations at all)"
out="$(run referrers-empty.json)"
check "total is zero"          "0"                        "$(jq -r '.total' <<<"$out")"
check "all groups missing"     '["sbom","provenance","vex"]' "$(jq -c '.groupsMissing' <<<"$out")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
