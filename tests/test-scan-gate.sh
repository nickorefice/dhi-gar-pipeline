#!/usr/bin/env bash
#
# Control-flow tests for the scan gate (.github/actions/scan/action.yaml).
#
# WHY THIS EXISTS. The gate's verdict now comes from docker-scout's EXIT CODE,
# because `docker scout cves` has no --format json and the population of its
# SARIF is undocumented. That makes the exit-code handling load-bearing in a way
# report-parsing never was -- and the failure mode is silent. Docker documents
# exactly one code ("2 if vulnerabilities are detected"), while scout-cli#213
# records a run that detected vulnerabilities and exited 255. The obvious
# implementation -- fail on 2, otherwise pass -- therefore treats both a crash
# and that 255 case as a clean bill of health.
#
# So the case that matters most here is `scout-exit-255`: it must block AND must
# leave the run manifest's scan gate on a non-passing status. A gate that
# crashed has approved nothing, and the promote stage reads the manifest rather
# than trusting stage ordering. This is the same regression that once let a
# CRITICAL CVE through with exit code 0, and it is asserted rather than assumed.
#
# The real docker-scout is replaced by a stub: `docker scout cves` needs network
# access to api.dso.docker.com, a live registry, and a real image, so exercising
# these branches against the real tool is not something a test suite can do.
# What IS tested is the pipeline's own logic -- the exit-code allowlist, the
# both-halves-must-pass composition, the suppression arithmetic, and the gate
# lifecycle -- using the ACTUAL run block extracted from the action YAML and the
# ACTUAL pipeline library, so what is tested is what runs.
#
#   ./tests/test-scan-gate.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"

python3 -c 'import yaml' 2>/dev/null \
  || { echo "python3+PyYAML not available -- skipping scan-gate tests"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/runner"

# The library and the stage body, both extracted from the YAML that CI runs.
"$TESTS_DIR/extract-pipeline-lib.sh" >"$WORK/runner/dhi-pipeline-lib.sh"
python3 - "$ROOT" <<'PY' >"$WORK/scan.sh"
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1] + "/.github/actions/scan/action.yaml"))
# The stage body is the step that carries the bash; the first step is the
# pipeline-env `uses:`, which has no run block.
runs = [s["run"] for s in doc["runs"]["steps"] if s.get("run")]
assert len(runs) == 1, f"expected exactly one run block in scan/action.yaml, found {len(runs)}"
sys.stdout.write(runs[0])
PY

# ---------------------------------------------------------------------------
# Stubs. docker-scout's behaviour is selected per-case by environment variable;
# the VEX-rejected pass always reports MORE findings than the suppressed one, so
# the suppression arithmetic is genuinely exercised rather than trivially zero.
# ---------------------------------------------------------------------------
cat >"$WORK/bin/docker-scout" <<'STUB'
#!/usr/bin/env bash
sub="$1"; shift
all="$*"                      # captured BEFORE the option loop consumes it
out=""; result=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)   out="$2"; shift 2 ;;
    --result-file) result="$2"; shift 2 ;;
    *) shift ;;
  esac
done
vex_rejected=0
[[ "$all" == *vex-disabled@invalid.test* ]] && vex_rejected=1
case "$sub" in
  version) echo "version: v1.23.1 (go1.26.6 - linux/amd64)"; exit 0 ;;
  sbom)
    case "${STUB_SBOM:-ok}" in
      ok)    printf '{"artifacts":[{"name":"glibc","purl":"pkg:deb/debian/glibc@2.41"},{"name":"libc6","purl":"pkg:deb/debian/libc6@2.41","parent":"pkg:deb/debian/glibc@2.41"}]}\n' >"$out"; exit 0 ;;
      empty) printf '{"artifacts":[]}\n' >"$out"; exit 0 ;;
      fail)  echo "sbom extraction failed" >&2; exit 1 ;;
    esac ;;
  cves)
    if (( vex_rejected )); then
      printf '{"runs":[{"results":[{"ruleId":"CVE-1111"},{"ruleId":"CVE-2222"}]}]}\n' >"$out"
      echo "Detected 2 vulnerable packages"; exit 2
    fi
    case "${STUB_GATE_CVES:-clean}" in
      clean)    printf '{"runs":[{"results":[]}]}\n' >"$out"; echo "No vulnerable package detected"; exit 0 ;;
      findings) printf '{"runs":[{"results":[{"ruleId":"CVE-9999"}]}]}\n' >"$out"; echo "Detected 1 vulnerable package"; exit 2 ;;
      broken)   echo "backend explosion" >&2; exit 255 ;;
      crash)    echo "could not list CVEs for the image" >&2; exit 1 ;;
    esac ;;
  policy)
    case "${STUB_POLICY:-pass}" in
      pass) printf '{"policies":[{"name":"dhi-provenance","pass":true,"violations":[]}]}\n' >"$result"; exit 0 ;;
      fail) printf '{"policies":[{"name":"dhi-provenance","pass":false,"violations":[{"message":"not a DHI: null","detail":{"marker":"com.docker.dhi.name","value":"<absent>","source":"labels"}}]}]}\n' >"$result"; exit 2 ;;
      broken) echo "opa exploded" >&2; exit 1 ;;
    esac ;;
  compare) echo "(stub compare)"; exit 0 ;;
esac
exit 0
STUB

cat >"$WORK/bin/regctl" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *"manifest head"*) echo "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999" ;;
  *"artifact get"*)  printf '{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1111"},"status":"not_affected","justification":"vulnerable_code_not_present"},{"vulnerability":{"name":"CVE-2222"},"status":"not_affected","justification":"inline_mitigations_already_exist"}]}' ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/"*

pass=0; fail=0
check() { # check <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"; pass=$((pass + 1))
  else printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

RUN_REL="out/dhi-node/26-debian13"

# Fixed, so the assertions can find the artefacts: run_scan is invoked inside a
# command substitution to capture the exit code, and a variable it set there
# would die with the subshell. The files on disk are what carry across.
CASE="$WORK/case"

# run_scan <sbom> <gate-cves> <policy> <skip-vex> -> exit code; artefacts under $CASE
run_scan() {
  rm -rf "$CASE"; mkdir -p "$CASE/$RUN_REL/attestations"
  cat >"$CASE/$RUN_REL/run-manifest.json" <<'J'
{"schemaVersion":1,"run":{"id":"test"},
 "source":{"registry":"docker.io","repository":"nicksdemoorg/dhi-node","tag":"26-debian13",
   "ref":"docker.io/nicksdemoorg/dhi-node:26-debian13",
   "indexDigest":"sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
   "platform":"linux/amd64","platformDigest":"sha256:1111",
   "platformsAvailable":["linux/amd64"],"inIndexAttestations":[]},
 "attestationSource":{"registry":"registry.scout.docker.com","repository":"nicksdemoorg/dhi-node","ref":"registry.scout.docker.com/nicksdemoorg/dhi-node"},
 "targets":{"quarantine":{},"prod":{}},"gates":{"verify":null,"scan":null},
 "stages":{"resolve":{"status":"pass"},"sync":null,"verify":null,"scan":null,"promote":null,"evidence":null}}
J
  # The verify gate leaves this behind; the scan gate reads it for VEX
  # justifications only.
  printf '{"artifacts":[{"class":"vex-openvex","digest":"sha256:vexvexvex"}]}\n' \
    >"$CASE/$RUN_REL/inventory-quarantine.json"
  cp -r "$ROOT/policy" "$CASE/policy"
  mkdir -p "$CASE/scripts/lib"; cp "$ROOT"/scripts/lib/*.jq "$CASE/scripts/lib/"
  cp "$ROOT/attestation-types.json" "$CASE/"

  local rc=0
  ( cd "$CASE"
    PATH="$WORK/bin:$PATH" RUNNER_TEMP="$WORK/runner" DHI_REPO_ROOT="$CASE" \
    GITHUB_STEP_SUMMARY="$CASE/summary.md" CONFIG_ENV=/nonexistent SKIP_LOGIN=1 \
    REPO=dhi-node TAG=26-debian13 GCP_PROJECT_ID=test-proj \
    GAR_LOCATION=us-central1 GAR_QUARANTINE_REPO=dhi-quarantine GAR_PROD_REPO=dhi-prod \
    DOCKERHUB_ORG=nicksdemoorg \
    STUB_SBOM="$1" STUB_GATE_CVES="$2" STUB_POLICY="$3" SKIP_VEX="$4" \
    bash "$WORK/scan.sh" >"$CASE/stdout.log" 2>"$CASE/stderr.log" ) || rc=$?
  echo "$rc"
}

report()      { jq -r "$1" "$CASE/$RUN_REL/scan-report.json" 2>/dev/null || echo MISSING; }
gate_status() { jq -r '.gates.scan.status // "none"' "$CASE/$RUN_REL/run-manifest.json" 2>/dev/null; }

# ---------------------------------------------------------------------------
echo "== a clean scan on a compliant image promotes"
rc="$(run_scan ok clean pass 0)"
check "exit 0"                              "0"      "$rc"
check "report status pass"                  "pass"   "$(report .status)"
check "manifest gate pass"                  "pass"   "$(gate_status)"
check "gating findings 0"                   "0"      "$(report .cves.gatingFindings)"
check "baseline findings recorded"          "2"      "$(report .cves.baselineFindings)"
check "suppression computed by difference"  "2"      "$(report .vex.suppressedCount)"
check "justification read from the referrer" "vulnerable_code_not_present" \
      "$(report '.vex.suppressed[0].vex.justification')"
check "sbom guard recorded the count"       "2"      "$(report .sbom.artifacts)"
check "rego half passed"                    "pass"   "$(report .rego.status)"

echo "== either half alone blocks the promotion"
rc="$(run_scan ok findings pass 0)"
check "cve findings: exit 1"                "1"      "$rc"
check "cve findings: gate fail"             "fail"   "$(gate_status)"
check "cve findings: rego still pass"       "pass"   "$(report .rego.status)"

rc="$(run_scan ok clean fail 0)"
check "policy violation: exit 1"            "1"      "$rc"
check "policy violation: gate fail"         "fail"   "$(gate_status)"
check "policy violation: cves still clean"  "0"      "$(report .cves.gatingFindings)"
check "policy violation surfaced"           "1"      "$(report '.rego.violations | length')"

# ---------------------------------------------------------------------------
# THE FAIL-OPEN CASES. Each of these must block, and none may leave a passing
# verdict in the manifest for the promote stage to read.
echo "== undocumented exit codes are tooling failures, never passes"
rc="$(run_scan ok broken pass 0)"
check "scout exit 255: blocks"              "1"      "$rc"
check "scout exit 255: NOT a pass"          "error"  "$(gate_status)"

rc="$(run_scan ok crash pass 0)"
check "scout exit 1: blocks"                "1"      "$rc"
check "scout exit 1: NOT a pass"            "error"  "$(gate_status)"

rc="$(run_scan ok clean broken 0)"
check "policy tooling failure: blocks"      "1"      "$rc"
check "policy tooling failure: NOT a pass"  "error"  "$(gate_status)"

echo "== a clean scan of an empty inventory is not evidence"
rc="$(run_scan empty clean pass 0)"
check "zero-package SBOM: blocks"           "1"      "$rc"
check "zero-package SBOM: NOT a pass"       "error"  "$(gate_status)"

rc="$(run_scan fail clean pass 0)"
check "unobtainable SBOM: blocks"           "1"      "$rc"
check "unobtainable SBOM: NOT a pass"       "error"  "$(gate_status)"

# ---------------------------------------------------------------------------
# skip-vex is the demo's negative test: the SAME digest that passes above must
# fail with the vendor's VEX rejected. If this ever passes, the negative test
# has stopped being negative -- see the --vex-author comment in the scan action.
echo "== skip-vex turns the passing digest into a blocked one"
rc="$(run_scan ok clean pass 1)"
check "skip-vex: blocks"                    "1"      "$rc"
check "skip-vex: gate fail"                 "fail"   "$(gate_status)"
check "skip-vex: records VEX not applied"   "false"  "$(report .vex.applied)"
check "skip-vex: findings now gate"         "2"      "$(report .cves.gatingFindings)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
