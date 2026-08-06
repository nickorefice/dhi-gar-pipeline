#!/usr/bin/env bash
#
# 10-sync.sh -- copy the image AND its attestations into the GAR quarantine repo.
#
# The single most important flag here is --referrers. Without it this is an
# ordinary mirror: the image arrives and every SBOM, provenance, and VEX document
# is silently left behind, leaving bytes with no proof attached.
#
# Two details that are easy to get wrong:
#
#   --referrers-src  DHI keeps attestations in registry.scout.docker.com, a
#                    DIFFERENT registry from the image. regctl will not find them
#                    unless told where to look, and finds nothing quietly if not.
#
#   digest-pinned    The copy reads from @sha256:... (resolved in stage 00), not
#   source           from :TAG. If the upstream tag moved between stages, a
#                    tag-based copy would pull content the gates never inspected.
#                    The TAG is still written at the target for human use.
#
#   REPO=dhi-node TAG=22 ./scripts/10-sync.sh

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool regctl jq
require_vars REPO TAG GCP_PROJECT_ID
load_manifest

SRC_DIGEST_REF="$(hub_repo)@$INDEX_DIGEST"
DST_TAG_REF="$(gar_ref quarantine)"
DST_REPO="$(gar_repo_path quarantine)"

step "10 sync: $SRC_DIGEST_REF -> $DST_TAG_REF"
log "digest (pinned by stage 00): $INDEX_DIGEST"
log "referrers source            : $SCOUT_SRC"
log "referrers target            : $DST_REPO"

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_dockerhub
  login_gar
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

# ---------------------------------------------------------------------------
# Pre-flight: are the attestations actually visible at the source?
#
# Checked BEFORE the copy because "0 referrers in GAR" afterwards is ambiguous --
# it could mean the copy dropped them or that there were never any to copy. Those
# have completely different fixes, so the distinction is worth one extra request.
# ---------------------------------------------------------------------------
step "10a pre-flight: source referrers"
SRC_SUBJECT="$SRC_DIGEST_REF"
[[ -n "$PLATFORM_DIGEST" ]] && SRC_SUBJECT="$(hub_repo)@$PLATFORM_DIGEST"
log "subject for referrer check: $SRC_SUBJECT"

SRC_REFERRERS="$RUN_DIR/referrers-source.json"
if fetch_referrers "$SRC_SUBJECT" "$SCOUT_SRC" >"$SRC_REFERRERS" 2>"$SRC_REFERRERS.err"; then
  SRC_COUNT="$(jq -r '(.manifests // []) | length' "$SRC_REFERRERS")"
  log "source referrers: $SRC_COUNT"
  if [[ "$SRC_COUNT" == "0" ]]; then
    warn "the attestation registry returned ZERO referrers for this subject."
    warn "the copy will still run, but expect the verify gate to fail. Diagnose with:"
    warn "  REPO=$REPO TAG=$TAG ./scripts/90-inspect-referrers.sh"
  else
    classify_referrers "$SRC_REFERRERS" \
      | jq -r '"  " + (.artifacts[] | .class + "  " + (.artifactType // .predicateType // "?"))' >&2
  fi
else
  warn "could not query referrers at the source:"
  sed 's/^/    /' "$SRC_REFERRERS.err" >&2
  printf '{"manifests":[]}' >"$SRC_REFERRERS"
  SRC_COUNT="0"
fi

# ---------------------------------------------------------------------------
# The copy
# ---------------------------------------------------------------------------
step "10b copy image + referrers"

# --referrers-tgt is the image's own GAR repo, so attestations land as NATIVE
# referrers in GAR. Upstream they are split across two registries; downstream they
# are not, which means consumers can query them with plain `regctl artifact list`
# and no --external.
#
# --force-recursive repairs partially-copied state, making a re-run after a failed
# sync converge instead of trusting whatever is already at the target. It costs
# extra manifest checks on every run; that is the right trade for a gate feeding
# a promotion decision.
COPY_ARGS=(
  "$SRC_DIGEST_REF"
  "$DST_TAG_REF"
  --referrers
  --referrers-src "$SCOUT_SRC"
  --referrers-tgt "$DST_REPO"
  --force-recursive
  --digest-tags
)

log "regctl image copy ${COPY_ARGS[*]}"
COPY_LOG="$RUN_DIR/sync-copy.log"
if ! regctl image copy -v info "${COPY_ARGS[@]}" >"$COPY_LOG" 2>&1; then
  err "regctl image copy FAILED -- full output:"
  sed 's/^/    /' "$COPY_LOG" >&2
  summary "### ❌ Sync failed"
  summary ""
  summary '```'
  summary "$(tail -30 "$COPY_LOG")"
  summary '```'
  die "sync failed; nothing was promoted"
fi
sed 's/^/    /' "$COPY_LOG" >&2 || true

# ---------------------------------------------------------------------------
# Immutability check: the digest must be identical at the target.
#
# This is hard rule #1 made testable. If these differ, something re-encoded or
# re-wrapped the image, and every attestation bound to the old digest is now
# orphaned -- so the run must stop here rather than promote something whose proof
# no longer applies.
# ---------------------------------------------------------------------------
step "10c verify the digest did not change"
DST_DIGEST="$(resolve_index_digest "$DST_TAG_REF")"
log "source digest: $INDEX_DIGEST"
log "target digest: $DST_DIGEST"

if [[ "$DST_DIGEST" != "$INDEX_DIGEST" ]]; then
  bad "digest changed during copy -- the image was mutated"
  summary "### ❌ Sync mutated the image"
  summary ""
  summary "| | |"
  summary "|---|---|"
  summary "| Source digest | \`$INDEX_DIGEST\` |"
  summary "| Target digest | \`$DST_DIGEST\` |"
  die "digest mismatch: attestations bound to $INDEX_DIGEST would be orphaned"
fi
ok "digest preserved: $DST_DIGEST"

# ---------------------------------------------------------------------------
# Record what landed
# ---------------------------------------------------------------------------
DST_PLATFORM_DIGEST="$(resolve_platform_digest "$DST_TAG_REF" "$VERIFY_PLATFORM")"
[[ -n "$DST_PLATFORM_DIGEST" ]] && log "target platform digest ($VERIFY_PLATFORM): $DST_PLATFORM_DIGEST"

# shellcheck disable=SC2016  # jq program: $vars are jq bindings from --arg, not shell
manifest_set '
  .targets.quarantine.digestRef = $digestRef
  | .targets.quarantine.indexDigest = $indexDigest
  | .targets.quarantine.platformDigest = (if $platformDigest == "" then null else $platformDigest end)
  | .stages.sync = { status: "pass", at: $at, sourceReferrerCount: ($srcCount | tonumber) }
' \
  --arg digestRef "$(gar_digest_ref quarantine "$DST_DIGEST")" \
  --arg indexDigest "$DST_DIGEST" \
  --arg platformDigest "$DST_PLATFORM_DIGEST" \
  --arg at "$(_ts)" \
  --arg srcCount "$SRC_COUNT"

summary "### Sync → quarantine"
summary ""
summary "| | |"
summary "|---|---|"
summary "| Target | \`$DST_TAG_REF\` |"
summary "| Digest | \`$DST_DIGEST\` (unchanged) |"
summary "| Source referrers seen | $SRC_COUNT |"

step "10 sync: OK"
log "next: ./scripts/20-verify.sh"
