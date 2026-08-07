#!/usr/bin/env bash
#
# 20-verify.sh -- GATE 1: did the attestations survive the copy, and is it still
# the same image?
#
# This gate is the reason the pipeline exists. Everything it checks is something
# that fails SILENTLY otherwise:
#
#   - A referrers query against the wrong subject returns an empty set with a zero
#     exit code. "No attestations" and "I asked the wrong question" are identical
#     from the caller's side.
#   - A digest that changed in transit means every attestation is bound to content
#     that is no longer what you are about to promote.
#   - A referrer whose type cannot be read from its descriptor will be reported as
#     a missing attestation unless its payload is opened (see classify_referrers_deep).
#
# Exits non-zero if any required check fails, which blocks promotion. Writes
# verify-report.json either way -- a failed gate must still produce evidence.
#
#   REPO=dhi-node TAG=22 ./scripts/20-verify.sh

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool regctl jq
require_vars REPO TAG GCP_PROJECT_ID
load_manifest

TARGET="${VERIFY_TARGET:-quarantine}"   # 40-promote.sh re-runs this against prod
QREPO="$(gar_repo_path "$TARGET")"
QTAG_REF="$(gar_ref "$TARGET")"
REPORT="$RUN_DIR/verify-report${TARGET:+-$TARGET}.json"
[[ "$TARGET" == "quarantine" ]] && REPORT="$RUN_DIR/verify-report.json"

step "20 verify: $QTAG_REF"
log "expected digest (from stage 00): $INDEX_DIGEST"

# Invalidate any previous verdict before doing anything that can fail. Only the
# quarantine pass owns the "verify" gate -- the prod re-check (VERIFY_TARGET=prod,
# invoked by 40-promote.sh) must not clobber it.
[[ "$TARGET" == "quarantine" ]] && gate_begin verify

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_gar
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

CHECKS='[]'
add_check() { # add_check <id> <status pass|fail|warn> <description> <detail>
  CHECKS="$(jq -c --arg id "$1" --arg st "$2" --arg d "$3" --arg det "$4" \
            '. + [{id: $id, status: $st, description: $d, detail: $det}]' <<<"$CHECKS")"
  case "$2" in
    pass) ok   "$3" ;;
    warn) warn "$3 -- $4" ;;
    *)    bad  "$3 -- $4" ;;
  esac
}

# ---------------------------------------------------------------------------
# Check 1 -- the image was not mutated.
#
# Compares what is live at the target RIGHT NOW against the digest stage 00
# resolved. Re-reading live rather than trusting what stage 10 recorded is the
# point: it catches anything that changed the target after the sync.
# ---------------------------------------------------------------------------
step "check 1: digest integrity"
LIVE_DIGEST="$(regctl manifest head "$QTAG_REF" --require-digest 2>/dev/null || true)"
if [[ -z "$LIVE_DIGEST" ]]; then
  add_check digest-integrity fail "image is present at $TARGET" \
    "could not resolve a digest for $QTAG_REF -- is it there?"
elif [[ "$LIVE_DIGEST" == "$INDEX_DIGEST" ]]; then
  add_check digest-integrity pass "digest matches source ($INDEX_DIGEST)" ""
else
  add_check digest-integrity fail "digest MISMATCH" \
    "source=$INDEX_DIGEST target=$LIVE_DIGEST -- attestations bound to the source digest do not describe this image"
fi

# ---------------------------------------------------------------------------
# Check 2 -- required attestations are present.
#
# Referrers are collected from BOTH the index digest and the platform digest and
# then merged. DHI may attach attestations to either, and asking only one of them
# is the difference between a passing gate and a confusing empty result.
# ---------------------------------------------------------------------------
step "check 2: attestation presence"

REFERRERS="$RUN_DIR/referrers-${TARGET}.json"
MERGED='{"manifests":[]}'
SUBJECTS_TRIED='[]'

for d in "$INDEX_DIGEST" "${PLATFORM_DIGEST:-}"; do
  [[ -n "$d" ]] || continue
  subject="$QREPO@$d"
  raw="$RUN_DIR/referrers-${TARGET}-${d#sha256:}.json"
  if fetch_referrers "$subject" "" >"$raw" 2>"$raw.err"; then
    n="$(jq -r '(.manifests // []) | length' "$raw" 2>/dev/null || echo 0)"
    log "subject ${d:0:19}... -> $n referrer(s)"
    SUBJECTS_TRIED="$(jq -c --arg s "$d" --argjson n "$n" '. + [{digest: $s, referrers: $n}]' <<<"$SUBJECTS_TRIED")"
    MERGED="$(jq -c --slurpfile add "$raw" \
      '.manifests = ((.manifests + ($add[0].manifests // [])) | unique_by(.digest))' <<<"$MERGED")"
  else
    warn "referrers query failed for ${d:0:19}...:"
    sed 's/^/    /' "$raw.err" >&2
    SUBJECTS_TRIED="$(jq -c --arg s "$d" '. + [{digest: $s, referrers: null, error: true}]' <<<"$SUBJECTS_TRIED")"
  fi
done

printf '%s' "$MERGED" | jq . >"$REFERRERS"
TOTAL="$(jq -r '(.manifests // []) | length' "$REFERRERS")"
log "merged unique referrers: $TOTAL"

# Deep classification: open anything whose type is not readable from its
# descriptor. The blobs live in the target repo because stage 10 copied them there
# as native referrers.
INVENTORY="$RUN_DIR/inventory-${TARGET}.json"
classify_referrers_deep "$REFERRERS" "$QREPO" >"$INVENTORY"

jq -r '.artifacts[] | "    " + (.class + (" " * (34 - (.class | length))))
       + (.artifactType // .predicateType // "?")
       + (if .deepResolved then "   [resolved from payload]" else "" end)' "$INVENTORY" >&2

MISSING="$(jq -c '.groupsMissing' "$INVENTORY")"
PRESENT="$(jq -c '.groupsPresent' "$INVENTORY")"
EXPECTED_MISSING="$(jq -c '.groupsExpectedMissing' "$INVENTORY")"
REQUIRED="$(jq -c '.groupsRequired' "$INVENTORY")"

if [[ "$TOTAL" == "0" ]]; then
  add_check attestations-present fail "required attestations present" \
    "ZERO referrers found at $TARGET. Either the copy dropped them (check 10-sync.sh's --referrers-src) or the source never had any. Diagnose: REPO=$REPO TAG=$TAG ./scripts/90-inspect-referrers.sh"
elif [[ "$MISSING" == "[]" ]]; then
  add_check attestations-present pass "required attestations present: $PRESENT (required: $REQUIRED)" ""
else
  add_check attestations-present fail "required attestations MISSING: $MISSING" \
    "found groups $PRESENT across $TOTAL referrer(s); required: $REQUIRED"
fi

# Expected-but-absent groups warn instead of failing. OpenVEX ships on
# debian-based DHI tags and not on alpine ones -- a property of the upstream
# image, not of this copy, so failing here would block an image for something the
# pipeline neither caused nor can fix. REQUIRE_VEX=1 makes it a hard requirement.
# Which groups are advisory *after* policy is applied: an expected group that
# REQUIRE_VEX promoted to required is no longer advisory.
EXPECTED_CONFIGURED="$(jq -c --argjson req "$REQUIRED" '(.expectedGroups // []) - $req' "$ATTESTATION_TYPES")"

if [[ "$EXPECTED_MISSING" != "[]" ]]; then
  add_check expected-attestations warn "expected but absent: $EXPECTED_MISSING" \
    "not present on this tag. If policy requires it, re-run with REQUIRE_VEX=1 to fail instead of warn. Note the scan gate will run unsuppressed without VEX."
elif [[ "$EXPECTED_CONFIGURED" == "[]" ]]; then
  # Everything that would merely be "expected" has been promoted to required by
  # policy, so there is nothing left for this check to soften. Saying "all present"
  # here would read as a contradiction next to a required-group failure.
  add_check expected-attestations pass "no advisory groups apply (all are required by policy)" ""
else
  add_check expected-attestations pass "all expected attestation groups present: $EXPECTED_CONFIGURED" ""
fi

# Unclassified referrers do not fail the gate -- an unrecognised extra attestation
# is not a security problem -- but they are reported, because an unclassified
# referrer is usually a matcher this repo has not learned yet.
UNCLASS="$(jq -r '.unclassified' "$INVENTORY")"
if [[ "$UNCLASS" != "0" ]]; then
  add_check no-unclassified warn "$UNCLASS referrer(s) could not be classified" \
    "$(jq -c '[.artifacts[] | select(.class == "unclassified") | {artifactType, predicateType}]' "$INVENTORY") -- add matchers to attestation-types.json"
else
  add_check no-unclassified pass "every referrer was classified" ""
fi

# ---------------------------------------------------------------------------
# Check 3 -- Docker Scout cross-check. INFORMATIONAL ONLY.
#
# Deliberately never fails the gate. Scout reading the attestations is a nice
# confirmation, but Scout not reading them out of GAR is a tooling/auth gap, not
# evidence about the image. regctl is the authority here; letting a second tool's
# auth quirks block a promotion would be the wrong dependency.
# ---------------------------------------------------------------------------
step "check 3: docker scout cross-check (informational)"
SCOUT_OUT="$RUN_DIR/scout-attest-list-${TARGET}.txt"
if docker scout version >/dev/null 2>&1; then
  if docker scout attest list --platform "$VERIFY_PLATFORM" \
       "registry://$QREPO@$LIVE_DIGEST" >"$SCOUT_OUT" 2>&1; then
    n_scout="$(grep -cE '^\s*(SBOM|Provenance|VEX|in-toto|https://)' "$SCOUT_OUT" 2>/dev/null || true)"
    add_check scout-crosscheck pass "docker scout read attestations from $TARGET (${n_scout:-0} line(s) matched)" ""
  else
    add_check scout-crosscheck warn "docker scout could not read attestations where regctl could" \
      "$(head -3 "$SCOUT_OUT" | tr '\n' ' ') -- tooling gap, not a gate failure"
  fi
else
  add_check scout-crosscheck warn "docker scout not installed" "skipped"
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
FAILED="$(jq -r '[.[] | select(.status == "fail")] | length' <<<"$CHECKS")"
WARNED="$(jq -r '[.[] | select(.status == "warn")] | length' <<<"$CHECKS")"
GATE_STATUS="pass"; [[ "$FAILED" == "0" ]] || GATE_STATUS="fail"

jq -n \
  --arg gate "verify" \
  --arg status "$GATE_STATUS" \
  --arg at "$(_ts)" \
  --arg target "$TARGET" \
  --arg ref "$QTAG_REF" \
  --arg expectedDigest "$INDEX_DIGEST" \
  --arg liveDigest "$LIVE_DIGEST" \
  --arg platform "$VERIFY_PLATFORM" \
  --argjson subjectsQueried "$SUBJECTS_TRIED" \
  --argjson checks "$CHECKS" \
  --slurpfile inventory "$INVENTORY" \
  '{
     gate: $gate, status: $status, at: $at,
     target: { name: $target, ref: $ref, platform: $platform },
     digest: { expected: $expectedDigest, live: $liveDigest,
               matches: ($expectedDigest == $liveDigest) },
     subjectsQueried: $subjectsQueried,
     attestations: $inventory[0],
     checks: $checks,
     summary: {
       failed: ($checks | map(select(.status == "fail")) | length),
       warned: ($checks | map(select(.status == "warn")) | length),
       passed: ($checks | map(select(.status == "pass")) | length)
     }
   }' >"$REPORT"

log "wrote ${REPORT#"$REPO_ROOT"/}"

if [[ "$TARGET" == "quarantine" ]]; then
  gate_end verify "$GATE_STATUS" \
    "$(jq -c '{summary, groupsPresent: .attestations.groupsPresent, groupsMissing: .attestations.groupsMissing}' "$REPORT")"
fi

# GitHub step summary -- a failed gate must say which check failed and why,
# without anyone opening the raw logs.
if [[ "$GATE_STATUS" == "pass" ]]; then
  summary "### ✅ Verify gate passed"
else
  summary "### ❌ Verify gate FAILED — promotion blocked"
fi
summary ""
summary "\`$QTAG_REF\` @ \`$LIVE_DIGEST\`"
summary ""
summary "| Check | Result | Detail |"
summary "|---|---|---|"
while read -r line; do summary "$line"; done < <(
  jq -r '.checks[] | "| " + .description + " | "
         + (if .status == "pass" then "✅ pass" elif .status == "warn" then "⚠️ warn" else "❌ **fail**" end)
         + " | " + (if .detail == "" then "—" else (.detail | gsub("\\|"; "\\\\|") | .[0:300]) end) + " |"' "$REPORT"
)
summary ""
summary "**Attestations found (${TOTAL}):**"
summary ""
while read -r line; do summary "$line"; done < <(
  jq -r '.attestations.artifacts[] | "- `" + .class + "` — " + (.artifactType // .predicateType // "?")
         + (if .deepResolved then " _(resolved from payload)_" else "" end)' "$REPORT"
)

if [[ "$GATE_STATUS" != "pass" ]]; then
  step "20 verify: FAILED ($FAILED check(s))"
  die "verify gate failed -- image stays in $TARGET, nothing promoted"
fi

step "20 verify: PASS${WARNED:+ ($WARNED warning(s))}"
log "next: ./scripts/30-scan.sh"
