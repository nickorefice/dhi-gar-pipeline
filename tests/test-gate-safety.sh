#!/usr/bin/env bash
#
# Regression tests for the promotion gate check.
#
# These exist because of a real bug, not a hypothetical one. A scan stage died on
# a tooling error before writing its result; the PREVIOUS run's "pass" was still
# in the run manifest; the promote stage read that pass and promoted an image
# carrying a CRITICAL CVE to the production registry, exiting 0. A crashing gate
# was indistinguishable from a passing one.
#
# Two mechanisms now prevent it, and both are asserted here:
#   1. gate_begin overwrites the verdict with "running" before anything that can
#      fail, and an EXIT trap converts a still-"running" gate into "error".
#   2. A verdict is only usable if it recorded the digest being promoted.
#
# The logic under test is promote_gate_check in the pipeline library, which
# lives inside .github/actions/pipeline-env/action.yaml -- the promote action
# calls it before any registry operation. The tests source the extracted
# library text, so the refusal code asserted here is byte-for-byte the code CI
# runs. No credentials or network needed.
#
#   ./tests/test-gate-safety.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"

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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

LIB_FILE="$WORK/pipeline-lib.sh"
"$TESTS_DIR/extract-pipeline-lib.sh" >"$LIB_FILE"

DIGEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"
OTHER="sha256:2222222222222222222222222222222222222222222222222222222222222222"

# Build a run manifest with the given verify/scan verdicts and recorded digests.
make_manifest() { # make_manifest <verify-status> <verify-digest> <scan-status> <scan-digest>
  local dir="$WORK/out/gatetest/v1"
  mkdir -p "$dir/attestations"
  jq -n --arg d "$DIGEST" \
        --arg vs "$1" --arg vd "$2" --arg ss "$3" --arg sd "$4" '{
    schemaVersion: 1,
    run: {id: "gate-safety-test", startedAt: "2026-01-01T00:00:00Z", actor: "test", runUrl: null},
    source: {registry: "docker.io", repository: "org/repo", tag: "v1", ref: "docker.io/org/repo:v1",
             digestRef: ("org/repo@" + $d), indexDigest: $d, mediaType: "x",
             platform: "linux/amd64", platformDigest: null, platformsAvailable: [], inIndexAttestations: []},
    attestationSource: {registry: "s", repository: "r", ref: "s/r"},
    targets: {quarantine: {repo: "q", tagRef: "q:v1", digestRef: ("q@" + $d), indexDigest: $d},
              prod: {repo: "p", tagRef: "p:v1", digestRef: null}},
    gates: {
      verify: (if $vs == "absent" then null
               else ({status: $vs} + (if $vd == "" then {} else {digest: $vd} end)) end),
      scan:   (if $ss == "absent" then null
               else ({status: $ss} + (if $sd == "" then {} else {digest: $sd} end)) end)
    },
    stages: {resolve: {status: "pass"}, sync: {status: "pass"}, verify: null, scan: null, promote: null, evidence: null}
  }' >"$dir/run-manifest.json"
}

# Run the promotion gate check exactly as the promote action does -- source the
# library, load that manifest, call promote_gate_check. Returns "refused" or
# "proceeded". A fresh bash -c per case so the library's set -e semantics match
# the composite step it normally runs in.
try_promote() {
  local out
  out="$(cd "$ROOT" && OUT_DIR="$WORK/out" REPO=gatetest TAG=v1 \
        GCP_PROJECT_ID=test-project CONFIG_ENV=/dev/null DHI_REPO_ROOT="$ROOT" \
        bash -c 'source "$0" && load_manifest && promote_gate_check' "$LIB_FILE" 2>&1)"
  if grep -qE 'refusing to promote|do not belong to the digest' <<<"$out"; then
    echo "refused"
  else
    # Anything that reached "both gates passed" (or died some other way) has
    # already gone wrong for these cases.
    echo "proceeded"
  fi
}

echo "== the bug that motivated this file"
# Scan crashed mid-run; gate_begin+trap must have left "error", never a stale pass.
make_manifest pass "$DIGEST" error "$DIGEST"
check "scan=error is refused"                    "refused" "$(try_promote)"

make_manifest pass "$DIGEST" running "$DIGEST"
check "scan=running (crashed before result) is refused" "refused" "$(try_promote)"

echo "== ordinary failure and absence"
make_manifest pass "$DIGEST" fail "$DIGEST"
check "scan=fail is refused"                     "refused" "$(try_promote)"

make_manifest pass "$DIGEST" absent ""
check "scan never run is refused"                "refused" "$(try_promote)"

make_manifest absent "" pass "$DIGEST"
check "verify never run is refused"              "refused" "$(try_promote)"

make_manifest fail "$DIGEST" pass "$DIGEST"
check "verify=fail is refused"                   "refused" "$(try_promote)"

echo "== digest binding: a pass must belong to the digest being promoted"
make_manifest pass "$OTHER" pass "$DIGEST"
check "verify verdict for a DIFFERENT digest is refused" "refused" "$(try_promote)"

make_manifest pass "$DIGEST" pass "$OTHER"
check "scan verdict for a DIFFERENT digest is refused"   "refused" "$(try_promote)"

make_manifest pass "" pass "$DIGEST"
check "verify pass with NO recorded digest is refused"   "refused" "$(try_promote)"

make_manifest pass "$DIGEST" pass ""
check "scan pass with NO recorded digest is refused"     "refused" "$(try_promote)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
