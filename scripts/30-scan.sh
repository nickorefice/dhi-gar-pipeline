#!/usr/bin/env bash
#
# 30-scan.sh -- GATE 2: vulnerability scan, with the vendor's VEX applied.
#
# The VEX part is the whole point. A hardened image routinely reports HIGH and
# CRITICAL CVEs that are not exploitable in that image -- the vulnerable code path
# is absent, the component is not reachable, or the distro has already patched it
# without bumping the version string the scanner matches on. DHI ships signed VEX
# statements saying exactly that. Scanning without them produces a wall of red
# that a team learns to ignore, which is worse than not scanning.
#
# So: Trivy WITH VEX is the gate. Grype is a second opinion and never blocks.
#
# Gate fails only on un-VEXed HIGH/CRITICAL from Trivy.
#
#   REPO=dhi-node TAG=22 ./scripts/30-scan.sh
#   REPO=dhi-node TAG=22 ./scripts/30-scan.sh --skip-vex   # negative test
#
# --skip-vex exists to demonstrate the gate biting: it scans the identical image
# with VEX suppressed, so the same digest that passes normally now fails and
# promotion is blocked. That contrast is the demo.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

SKIP_VEX=0
for arg in "$@"; do
  case "$arg" in
    --skip-vex) SKIP_VEX=1 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $arg (try --skip-vex)" ;;
  esac
done

need_tool regctl trivy jq
require_vars REPO TAG GCP_PROJECT_ID
load_manifest

QREPO="$(gar_repo_path quarantine)"
SCAN_REF="$QREPO@$INDEX_DIGEST"      # digest-pinned, never the tag
REPORT="$RUN_DIR/scan-report.json"
VEX_DIR="$RUN_DIR/attestations"
mkdir -p "$VEX_DIR"

step "30 scan: $SCAN_REF"
log "digest (pinned by stage 00): $INDEX_DIGEST"
log "platform: $VERIFY_PLATFORM"
(( SKIP_VEX )) && warn "--skip-vex: VEX will NOT be applied (negative test)"

# Invalidate any previous verdict before doing anything that can fail.
gate_begin scan

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_gar
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

# ---------------------------------------------------------------------------
# 1. Extract VEX documents from the referrers.
#
# Two payload shapes have to be handled. A VEX referrer may be a bare OpenVEX
# document, or an in-toto Statement whose .predicate holds the OpenVEX. Scanners
# expect the bare document, so the Statement wrapper is unwrapped here. Feeding
# a scanner the wrapper produces no error -- it just silently applies no VEX,
# which would make this gate quietly meaningless.
# ---------------------------------------------------------------------------
step "30a extract VEX from referrers"

INVENTORY="$RUN_DIR/inventory-quarantine.json"
if [[ ! -f "$INVENTORY" ]]; then
  log "no inventory from the verify gate; classifying referrers now"
  REF="$RUN_DIR/referrers-quarantine.json"
  if [[ ! -f "$REF" ]]; then
    fetch_referrers "$SCAN_REF" "" >"$REF" 2>/dev/null || printf '{"manifests":[]}' >"$REF"
  fi
  classify_referrers_deep "$REF" "$QREPO" >"$INVENTORY"
fi

VEX_FILES=()
VEX_COUNT=0
while read -r digest; do
  [[ -n "$digest" ]] || continue
  VEX_COUNT=$((VEX_COUNT + 1))
  out="$VEX_DIR/vex.openvex.$(printf '%02d' "$VEX_COUNT").json"
  raw="$(regctl artifact get "$QREPO@$digest" 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    warn "could not download VEX referrer ${digest:0:19}..."
    VEX_COUNT=$((VEX_COUNT - 1))
    continue
  fi
  # Unwrap an in-toto Statement if that is what we got.
  if jq -e 'type == "object" and has("predicate") and has("predicateType")' >/dev/null 2>&1 <<<"$raw"; then
    jq '.predicate' <<<"$raw" >"$out"
    log "VEX $VEX_COUNT: unwrapped from in-toto Statement -> ${out##*/}"
  else
    jq '.' <<<"$raw" >"$out"
    log "VEX $VEX_COUNT: bare OpenVEX document -> ${out##*/}"
  fi
  # Sanity-check it looks like OpenVEX before handing it to a scanner.
  if ! jq -e 'has("@context") or has("statements")' >/dev/null 2>&1 <<<"$(cat "$out")"; then
    warn "  ${out##*/} does not look like OpenVEX (no @context / statements) -- scanners may ignore it"
  fi
  VEX_FILES+=("$out")
done < <(jq -r '.artifacts[] | select(.class == "vex-openvex") | .digest' "$INVENTORY" 2>/dev/null || true)

log "VEX documents extracted: $VEX_COUNT"
if (( VEX_COUNT == 0 )); then
  warn "no VEX documents found. The scan will run unsuppressed, so a hardened"
  warn "image may report CVEs its vendor has already assessed as not affecting it."
fi

# ---------------------------------------------------------------------------
# 2. Trivy -- THE GATE
# ---------------------------------------------------------------------------
step "30b trivy (gate)"

TRIVY_JSON="$RUN_DIR/trivy-report.json"
TRIVY_BASELINE_JSON="$RUN_DIR/trivy-report-baseline.json"
TRIVY_TXT="$RUN_DIR/trivy-report.txt"

# --image-src remote is REQUIRED, not a preference.
#
# Trivy otherwise tries the local Docker daemon first. That produced a hard failure
# here against a stale daemon cache entry -- but the quiet case is worse: if the
# daemon happens to hold something for that reference, Trivy scans LOCAL content
# while the report names a registry digest. In a digest-pinned pipeline whose whole
# claim is "the thing we scanned is the thing we promoted", scanning a local cache
# breaks that claim silently.
TRIVY_BASE_ARGS=(image "$SCAN_REF" --image-src remote --platform "$VERIFY_PLATFORM" \
                 --severity "$SCAN_SEVERITY" --scanners vuln)

run_trivy() { # run_trivy <output-file> [extra args...]
  local out="$1"; shift
  # --exit-code 0 always: the gate decision is made from the report contents, not
  # from trivy's exit status. "trivy found issues" and "trivy failed to run" are
  # different outcomes and must never be conflated -- the second one is a tooling
  # failure, not a clean bill of health.
  trivy "${TRIVY_BASE_ARGS[@]}" "$@" --format json --output "$out" --exit-code 0 2>"$out.err"
}

# Pass 1 -- BASELINE, no VEX. This is what an ordinary scanner reports about a
# hardened image, and it is the number a customer is used to seeing.
log "trivy pass 1/2: baseline (no VEX)"
if ! run_trivy "$TRIVY_BASELINE_JSON"; then
  err "trivy failed to run:"
  sed 's/^/    /' "$TRIVY_BASELINE_JSON.err" >&2
  summary "### ❌ Scan gate error"
  summary ""
  summary '```'
  summary "$(tail -20 "$TRIVY_BASELINE_JSON.err")"
  summary '```'
  die "trivy could not scan $SCAN_REF (tooling failure, NOT a clean bill of health)"
fi

# Pass 2 -- the GATE, with the vendor's VEX applied (unless --skip-vex).
TRIVY_VEX_ARGS=()
if (( ! SKIP_VEX )); then
  for f in "${VEX_FILES[@]:-}"; do [[ -n "$f" ]] && TRIVY_VEX_ARGS+=(--vex "$f"); done
fi
log "trivy pass 2/2: gate ($( (( SKIP_VEX )) && echo 'VEX SUPPRESSED by --skip-vex' || echo "${#TRIVY_VEX_ARGS[@]} VEX arg(s)"))"

# Expanded via an explicit length test, NOT "${ARR[@]:-}". On an empty array that
# form yields a single empty-string argument, which Trivy rejects as bad usage --
# so --skip-vex died as a tooling error instead of failing the gate, which is the
# opposite of what a negative test is for.
if (( ${#TRIVY_VEX_ARGS[@]} )); then
  run_trivy_gate() { run_trivy "$1" "${TRIVY_VEX_ARGS[@]}"; }
  trivy_table() { trivy "${TRIVY_BASE_ARGS[@]}" "${TRIVY_VEX_ARGS[@]}" --format table --exit-code 0; }
else
  run_trivy_gate() { run_trivy "$1"; }
  trivy_table() { trivy "${TRIVY_BASE_ARGS[@]}" --format table --exit-code 0; }
fi

if ! run_trivy_gate "$TRIVY_JSON"; then
  err "trivy failed to run (VEX pass):"
  sed 's/^/    /' "$TRIVY_JSON.err" >&2
  die "trivy could not scan $SCAN_REF with VEX applied"
fi

# Human-readable pass for the demo.
trivy_table >"$TRIVY_TXT" 2>/dev/null || true
sed 's/^/    /' "$TRIVY_TXT" >&2 || true

extract_findings() {
  jq '[ (.Results // [])[] | (.Vulnerabilities // [])[]
        | select(.Severity == "HIGH" or .Severity == "CRITICAL") ]' "$1"
}

BASELINE="$(extract_findings "$TRIVY_BASELINE_JSON")"
GATING="$(extract_findings "$TRIVY_JSON")"
BASELINE_COUNT="$(jq '[ .[] | .VulnerabilityID ] | unique | length' <<<"$BASELINE")"
GATING_COUNT="$(jq 'length' <<<"$GATING")"

# Suppressed = baseline minus gating, computed by set difference.
#
# Deliberately NOT read from Trivy's .ModifiedFindings: with --vex from a file,
# Trivy 0.73 drops matched findings without populating that field (verified, even
# with --show-suppressed). Trusting it would silently report "0 suppressed" and
# throw away the most informative number this gate produces -- the count of CVEs
# the vendor has already assessed as not affecting this image.
#
# Each suppression is annotated with the justification from the VEX document, so
# the report says WHY a CVE was set aside rather than just that it was.
VEX_INDEX='{}'
for f in "${VEX_FILES[@]:-}"; do
  [[ -n "$f" && -f "$f" ]] || continue
  VEX_INDEX="$(jq -c --slurpfile v "$f" '
    . + ( ($v[0].statements // [])
          | map({ key: (.vulnerability.name // .vulnerability // "?" | tostring),
                  value: { status, justification, impact_statement } })
          | from_entries )' <<<"$VEX_INDEX")"
done

SUPPRESSED="$(jq -c --argjson gating "$GATING" --argjson vex "$VEX_INDEX" '
  ([ $gating[] | .VulnerabilityID ] | unique) as $survived
  | [ .[] | select([.VulnerabilityID] | inside($survived) | not) ]
  | group_by(.VulnerabilityID) | map(.[0])
  | map({ id: .VulnerabilityID, severity: .Severity, pkg: .PkgName,
          installed: .InstalledVersion,
          vex: ($vex[.VulnerabilityID] // null) })' <<<"$BASELINE")"
SUPPRESSED_COUNT="$(jq 'length' <<<"$SUPPRESSED")"

log "HIGH/CRITICAL without VEX (baseline): $BASELINE_COUNT"
log "suppressed by vendor VEX            : $SUPPRESSED_COUNT"
log "HIGH/CRITICAL gating the promotion  : $GATING_COUNT"

if (( SUPPRESSED_COUNT > 0 )); then
  jq -r '.[] | "    SUPPRESSED  " + .severity + "  " + .id + "  " + (.pkg // "?")
         + (if .vex then "\n                justification: " + (.vex.justification // "none given") else "" end)' \
    <<<"$SUPPRESSED" >&2
fi

if (( GATING_COUNT > 0 )); then
  jq -r 'group_by(.VulnerabilityID)[] | .[0]
         | "    " + .Severity + "  " + .VulnerabilityID + "  " + (.PkgName // "?")
           + " " + (.InstalledVersion // "?")
           + (if .FixedVersion then " -> fixed in " + .FixedVersion else " (no fix available)" end)' \
    <<<"$GATING" >&2
fi

# ---------------------------------------------------------------------------
# 3. Grype -- second opinion, never gates.
#
# A different vulnerability database and matcher. Where the two disagree, that
# disagreement is itself useful signal for a customer conversation -- but a demo
# should not be blocked by whichever scanner happens to be noisier this week.
# ---------------------------------------------------------------------------
step "30c grype (second opinion, report-only)"
GRYPE_JSON="$RUN_DIR/grype-report.json"
GRYPE_COUNT="null"
if command -v grype >/dev/null 2>&1; then
  GRYPE_ARGS=("$SCAN_REF" --platform "$VERIFY_PLATFORM" -o json)
  if (( ! SKIP_VEX )); then
    for f in "${VEX_FILES[@]:-}"; do [[ -n "$f" ]] && GRYPE_ARGS+=(--vex "$f"); done
  fi
  if grype "${GRYPE_ARGS[@]}" >"$GRYPE_JSON" 2>"$GRYPE_JSON.err"; then
    GRYPE_COUNT="$(jq '[ (.matches // [])[]
                         | select((.vulnerability.severity // "") | ascii_downcase
                                  | . == "high" or . == "critical") ] | length' "$GRYPE_JSON")"
    log "grype HIGH/CRITICAL: $GRYPE_COUNT"
    if [[ "$GRYPE_COUNT" != "$GATING_COUNT" ]]; then
      warn "grype ($GRYPE_COUNT) and trivy ($GATING_COUNT) disagree -- expected; different DBs and matchers"
    fi
  else
    warn "grype failed (report-only, gate unaffected):"
    sed 's/^/    /' "$GRYPE_JSON.err" >&2 | head -5
  fi
else
  warn "grype not installed -- skipping second opinion"
fi

# ---------------------------------------------------------------------------
# 4. docker scout compare against what is in prod today.
#
# This is the view that replaces a manual pull-scan-eyeball workflow: not "how
# many CVEs does this image have" but "what changes if I promote it".
# ---------------------------------------------------------------------------
step "30d docker scout compare vs prod"
COMPARE_TXT="$RUN_DIR/scout-compare.txt"
COMPARE_STATUS="skipped"
PROD_TAG_REF="$(gar_ref prod)"

if ! command -v docker >/dev/null 2>&1 || ! docker scout version >/dev/null 2>&1; then
  warn "docker scout unavailable -- skipping comparison"
  COMPARE_STATUS="unavailable"
elif ! PROD_DIGEST="$(regctl manifest head "$PROD_TAG_REF" --require-digest 2>/dev/null)"; then
  log "nothing in prod at $PROD_TAG_REF yet -- first run, nothing to compare against"
  COMPARE_STATUS="no-baseline"
elif [[ "$PROD_DIGEST" == "$INDEX_DIGEST" ]]; then
  log "prod already at $INDEX_DIGEST -- identical, comparison would be empty"
  COMPARE_STATUS="identical"
else
  log "comparing $INDEX_DIGEST (candidate) against $PROD_DIGEST (prod)"
  if docker scout compare --to "registry://$(gar_repo_path prod)@$PROD_DIGEST" \
       "registry://$SCAN_REF" --platform "$VERIFY_PLATFORM" >"$COMPARE_TXT" 2>&1; then
    COMPARE_STATUS="ok"
    sed 's/^/    /' "$COMPARE_TXT" >&2 | head -40
  else
    COMPARE_STATUS="failed"
    warn "docker scout compare failed (informational, gate unaffected):"
    sed 's/^/    /' "$COMPARE_TXT" >&2 | head -10
  fi
fi

# ---------------------------------------------------------------------------
# 5. Report + gate decision
# ---------------------------------------------------------------------------
GATE_STATUS="pass"
(( GATING_COUNT > 0 )) && GATE_STATUS="fail"

jq -n \
  --arg gate "scan" \
  --arg status "$GATE_STATUS" \
  --arg at "$(_ts)" \
  --arg ref "$SCAN_REF" \
  --arg digest "$INDEX_DIGEST" \
  --arg platform "$VERIFY_PLATFORM" \
  --arg severity "$SCAN_SEVERITY" \
  --argjson vexApplied "$(( SKIP_VEX ? 0 : 1 ))" \
  --argjson vexDocuments "$VEX_COUNT" \
  --argjson gatingCount "$GATING_COUNT" \
  --argjson baselineCount "$BASELINE_COUNT" \
  --argjson suppressedByVex "$SUPPRESSED_COUNT" \
  --argjson suppressedDetail "$SUPPRESSED" \
  --argjson grypeCount "${GRYPE_COUNT:-null}" \
  --arg compareStatus "$COMPARE_STATUS" \
  --argjson findings "$(jq '[ group_by(.VulnerabilityID)[] | .[0]
                              | {id: .VulnerabilityID, severity: .Severity, pkg: .PkgName,
                                 installed: .InstalledVersion, fixed: .FixedVersion,
                                 title: (.Title // null)} ]' <<<"$GATING")" \
  '{
     gate: $gate, status: $status, at: $at,
     target: { ref: $ref, digest: $digest, platform: $platform },
     policy: { severity: $severity, vexApplied: ($vexApplied == 1),
               gateFailsOn: "un-VEXed HIGH/CRITICAL from Trivy" },
     vex: { documents: $vexDocuments,
            suppressedCount: $suppressedByVex,
            suppressed: $suppressedDetail,
            note: "suppressedCount is computed as (baseline findings - findings surviving VEX), not read from Trivy .ModifiedFindings, which is not populated for file-based VEX" },
     trivy: { baselineFindings: $baselineCount,
              gatingFindings: $gatingCount,
              findings: $findings,
              note: "baselineFindings is what a scanner reports with no VEX applied; gatingFindings is what remains after vendor VEX and is what blocks promotion" },
     grype: { gatingFindings: $grypeCount, note: "second opinion; never gates" },
     scoutCompare: { status: $compareStatus }
   }' >"$REPORT"

log "wrote ${REPORT#"$REPO_ROOT"/}"

gate_end scan "$GATE_STATUS" \
  "$(jq -c '{vex, trivy: {baselineFindings: .trivy.baselineFindings, gatingFindings: .trivy.gatingFindings}, policy}' "$REPORT")"

if [[ "$GATE_STATUS" == "pass" ]]; then
  summary "### ✅ Scan gate passed"
else
  summary "### ❌ Scan gate FAILED — promotion blocked"
fi
summary ""
summary "| | |"
summary "|---|---|"
summary "| Image | \`$SCAN_REF\` |"
summary "| Threshold | $SCAN_SEVERITY |"
if (( SKIP_VEX )); then VEX_CELL="**no** (--skip-vex)"; else VEX_CELL="yes ($VEX_COUNT document(s))"; fi
summary "| VEX applied | $VEX_CELL |"
summary "| Findings without VEX (baseline) | $BASELINE_COUNT |"
summary "| Suppressed by vendor VEX | $SUPPRESSED_COUNT |"
summary "| **Gating findings** | **$GATING_COUNT** |"
summary "| Grype (report-only) | ${GRYPE_COUNT:-n/a} |"
summary "| Scout compare | $COMPARE_STATUS |"

if (( SUPPRESSED_COUNT > 0 )); then
  summary ""
  summary "**Suppressed by the vendor's signed VEX** — assessed as not affecting this image:"
  summary ""
  summary "| Severity | CVE | Package | Justification |"
  summary "|---|---|---|---|"
  while read -r line; do summary "$line"; done < <(
    jq -r '.vex.suppressed[] | "| " + .severity + " | " + .id + " | " + (.pkg // "?")
           + " | " + (.vex.justification // "_not stated_") + " |"' "$REPORT"
  )
fi

if (( GATING_COUNT > 0 )); then
  summary ""
  summary "**Un-VEXed HIGH/CRITICAL:**"
  summary ""
  summary "| Severity | CVE | Package | Installed | Fixed |"
  summary "|---|---|---|---|---|"
  while read -r line; do summary "$line"; done < <(
    jq -r '.trivy.findings[] | "| " + .severity + " | " + .id + " | " + (.pkg // "?")
           + " | " + (.installed // "?") + " | " + (.fixed // "_none_") + " |"' "$REPORT"
  )
fi

if [[ "$GATE_STATUS" != "pass" ]]; then
  step "30 scan: FAILED ($GATING_COUNT un-VEXed HIGH/CRITICAL)"
  die "scan gate failed -- image stays in quarantine, nothing promoted"
fi

step "30 scan: PASS"
log "next: ./scripts/40-promote.sh"
