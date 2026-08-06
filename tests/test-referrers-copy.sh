#!/usr/bin/env bash
#
# End-to-end test of the referrers mechanics -- with no registry, no network, and
# no credentials.
#
# regctl speaks to `ocidir://` OCI layouts with the same code path it uses for a
# real registry, so the DHI topology can be reproduced exactly on local disk:
# the image in one repository, its attestations in ANOTHER (which is what
# registry.scout.docker.com is), and a copy that has to carry them across.
#
# What this pins down:
#   1. Querying referrers without --external returns 0 and does NOT error.
#      This is the pipeline's central failure mode -- a mirror that looks
#      successful while silently dropping every attestation.
#   2. A naive `regctl image copy` preserves the digest and loses all proof.
#   3. `--referrers --referrers-src --referrers-tgt` preserves both.
#   4. Attestations land as NATIVE referrers at the target, so consumers need no
#      --external against GAR even though the source required it.
#   5. Descriptor-only classification is not sufficient: an in-toto referrer with
#      no annotations needs its payload opened before provenance can be claimed.
#
#   ./tests/test-referrers-copy.sh

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"

command -v regctl >/dev/null 2>&1 || { echo "regctl not installed -- run 'make tools'"; exit 1; }

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

# ocidir:// paths are resolved relative to the working directory, so the whole
# fixture is built inside one scratch dir we cd into. (Getting this wrong makes
# regctl report "not found" for a layout that exists.)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

n_referrers() { jq -r '(.manifests // []) | length' "$1"; }

# ---------------------------------------------------------------------------
# Fixture: an image, and three attestations held in a separate repository.
# ---------------------------------------------------------------------------
echo '{"spdxVersion":"SPDX-2.3","name":"test-sbom","packages":[]}'                                              > sbom.spdx.json
echo '{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","predicate":{}}' > prov.json
echo '{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}'                                            > vex.json
echo 'test layer content'                                                                                      > layer.txt

regctl artifact put --artifact-type application/vnd.oci.image.config.v1+json \
  -f layer.txt -m text/plain --file-title ocidir://img:v1 >/dev/null
SUBJ="$(regctl manifest head ocidir://img:v1 --require-digest)"

# NOTE: provenance is attached with artifactType application/vnd.in-toto+json and
# NO predicate annotation -- deliberately. That is a valid encoding and the one
# that breaks descriptor-only classifiers.
for spec in "application/spdx+json:sbom.spdx.json" \
            "application/vnd.in-toto+json:prov.json" \
            "application/vnd.openvex+json:vex.json"; do
  regctl artifact put --artifact-type "${spec%%:*}" \
    -f "${spec##*:}" -m application/json --file-title \
    --subject "ocidir://img@$SUBJ" --external ocidir://attest --by-digest >/dev/null
done

echo "== source referrer visibility"
regctl artifact list "ocidir://img@$SUBJ" --external ocidir://attest --format body > src-external.json
check "3 referrers via --external" "3" "$(n_referrers src-external.json)"

regctl artifact list "ocidir://img@$SUBJ" --format body > src-native.json 2>/dev/null \
  || printf '{"manifests":[]}' > src-native.json
check "0 referrers without --external (silent, not an error)" "0" "$(n_referrers src-native.json)"

echo "== naive copy loses the attestations"
regctl image copy "ocidir://img@$SUBJ" ocidir://naive:v1 >/dev/null 2>&1
check "naive copy preserves digest" "$SUBJ" "$(regctl manifest head ocidir://naive:v1 --require-digest)"
regctl artifact list ocidir://naive:v1 --format body > naive-list.json 2>/dev/null \
  || printf '{"manifests":[]}' > naive-list.json
check "naive copy carries 0 attestations" "0" "$(n_referrers naive-list.json)"

echo "== pipeline copy preserves them"
regctl image copy "ocidir://img@$SUBJ" ocidir://dst:v1 \
  --referrers --referrers-src ocidir://attest --referrers-tgt ocidir://dst \
  --force-recursive --digest-tags >/dev/null 2>&1
DSTD="$(regctl manifest head ocidir://dst:v1 --require-digest)"
check "pipeline copy preserves digest" "$SUBJ" "$DSTD"

# No --external here: at the target the attestations are native referrers, which
# is the end state the pipeline is trying to produce in GAR.
regctl artifact list "ocidir://dst@$DSTD" --format body > dst-list.json
check "3 attestations survive, queryable natively" "3" "$(n_referrers dst-list.json)"

echo "== classification requires opening generic referrers"
shallow="$(classify_referrers dst-list.json)"
check "shallow: provenance NOT provable from descriptors" '["provenance"]' "$(jq -c '.groupsMissing' <<<"$shallow")"
check "shallow: in-toto falls back to generic" "attestation-manifest-generic" \
  "$(jq -r '.artifacts[] | select(.artifactType == "application/vnd.in-toto+json") | .class' <<<"$shallow")"

deep="$(classify_referrers_deep dst-list.json ocidir://dst 2>/dev/null)"
check "deep: no groups missing" "[]" "$(jq -c '.groupsMissing' <<<"$deep")"
check "deep: all three groups present" '["provenance","sbom","vex"]' "$(jq -c '.groupsPresent' <<<"$deep")"
check "deep: provenance resolved from payload" "provenance-slsa" \
  "$(jq -r '.artifacts[] | select(.artifactType == "application/vnd.in-toto+json") | .class' <<<"$deep")"
check "deep: predicate type recovered" "https://slsa.dev/provenance/v1" \
  "$(jq -r '.artifacts[] | select(.class == "provenance-slsa") | .predicateType' <<<"$deep")"
check "deep: resolution is recorded, not silent" "1" "$(jq -r '.deepResolvedCount' <<<"$deep")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
