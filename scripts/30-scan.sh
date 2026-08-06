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
TRIVY_TXT="$RUN_DIR/trivy-report.txt"

TRIVY_ARGS=(image "$SCAN_REF" --platform "$VERIFY_PLATFORM" --severity "$SCAN_SEVERITY" --scanners vuln)
if (( ! SKIP_VEX )); then
  for f in "${VEX_FILES[@]:-}"; do [[ -n "$f" ]] && TRIVY_ARGS+=(--vex "$f"); done
fi

# JSON pass: --exit-code 0 so we always get a parseable report; the gate decision
# is made from the report contents, not from trivy's exit status. Trivy exiting
# non-zero and trivy failing to run are different things and must not be conflated.
log "trivy ${TRIVY_ARGS[*]} --format json"
if ! trivy "${TRIVY_ARGS[@]}" --format json --output "$TRIVY_JSON" --exit-code 0 2>"$TRIVY_TXT.err"; then
  err "trivy failed to run:"
  sed 's/^/    /' "$TRIVY_TXT.err" >&2
  summary "### ❌ Scan gate error"
  summary ""
  summary '```'
  summary "$(tail -20 "$TRIVY_TXT.err")"
  summary '```'
  die "trivy could not scan $SCAN_REF (this is a tooling failure, not a clean bill of health)"
fi

# Human-readable pass for the demo.
trivy "${TRIVY_ARGS[@]}" --format table --exit-code 0 >"$TRIVY_TXT" 2>/dev/null || true
sed 's/^/    /' "$TRIVY_TXT" >&2 || true

# Findings that survived VEX. Trivy moves VEX-suppressed findings out of
# .Vulnerabilities into .ModifiedFindings, so counting .Vulnerabilities gives
# exactly "what VEX did not explain away".
GATING="$(jq '[ (.Results // [])[] | (.Vulnerabilities // [])[]
                | select(.Severity == "HIGH" or .Severity == "CRITICAL") ]' "$TRIVY_JSON")"
GATING_COUNT="$(jq 'length' <<<"$GATING")"
SUPPRESSED_COUNT="$(jq '[ (.Results // [])[] | (.ModifiedFindings // [])[] ] | length' "$TRIVY_JSON")"

log "HIGH/CRITICAL after VEX : $GATING_COUNT"
log "suppressed by VEX       : $SUPPRESSED_COUNT"

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
  --argjson suppressedByVex "$SUPPRESSED_COUNT" \
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
     vex: { documents: $vexDocuments, suppressedFindings: $suppressedByVex },
     trivy: { gatingFindings: $gatingCount, findings: $findings },
     grype: { gatingFindings: $grypeCount, note: "second opinion; never gates" },
     scoutCompare: { status: $compareStatus }
   }' >"$REPORT"

log "wrote ${REPORT#"$REPO_ROOT"/}"

# shellcheck disable=SC2016  # jq program: $vars are jq bindings from --arg
manifest_set '.gates.scan = $v | .stages.scan = {status: $st, at: $at}' \
  --argjson v "$(jq -c '{status, vex, trivy: {gatingFindings: .trivy.gatingFindings}, policy}' "$REPORT")" \
  --arg st "$GATE_STATUS" --arg at "$(_ts)"

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
summary "| Suppressed by VEX | $SUPPRESSED_COUNT |"
summary "| **Gating findings** | **$GATING_COUNT** |"
summary "| Grype (report-only) | ${GRYPE_COUNT:-n/a} |"
summary "| Scout compare | $COMPARE_STATUS |"

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
