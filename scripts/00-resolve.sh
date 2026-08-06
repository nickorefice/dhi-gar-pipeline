#!/usr/bin/env bash
#
# 00-resolve.sh -- resolve tag -> digest ONCE and write the run manifest.
#
# This is the only stage permitted to look at a tag. Everything after it reads
# digests from out/<repo>/<tag>/run-manifest.json. That is not ceremony: DHI tags
# move (that is the point of a mirrored, continuously-rebuilt hardened image), and
# a pipeline that re-resolved the tag per stage could verify one digest, scan a
# second, and promote a third without a single error being raised.
#
#   REPO=dhi-node TAG=22 ./scripts/00-resolve.sh
#
# Env:
#   SKIP_LOGIN=1   reuse credentials already in ~/.docker/config.json

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool regctl jq
require_vars REPO TAG
init_run_dir

HUB_REF="$(hub_ref)"
HUB_REPO="$(hub_repo)"

step "00 resolve: $HUB_REF"

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_dockerhub
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------
INDEX_DIGEST="$(resolve_index_digest "$HUB_REF")"
log "RESOLVED index digest: $INDEX_DIGEST"

MEDIA_TYPE="$(regctl manifest get "$HUB_REPO@$INDEX_DIGEST" --format '{{.GetDescriptor.MediaType}}' 2>/dev/null || echo "unknown")"
log "media type: $MEDIA_TYPE"

# Enumerate platforms. A DHI tag is normally a multi-platform index; a
# single-platform image yields an empty list here and must still work.
PLATFORMS_JSON="$(
  regctl manifest get "$HUB_REPO@$INDEX_DIGEST" --format body 2>/dev/null \
    | jq -c '[ (.manifests // [])[]
               | select((.annotations // {})["vnd.docker.reference.type"] == null)
               | select(.platform.os != "unknown")
               | ((.platform.os // "?") + "/" + (.platform.architecture // "?")
                  + (if .platform.variant then "/" + .platform.variant else "" end)) ]' \
    2>/dev/null || echo '[]'
)"
log "platforms: $(jq -r 'if length == 0 then "(single-platform image)" else join(", ") end' <<<"$PLATFORMS_JSON")"

# Attestation-carrying entries in a BuildKit-style index are marked with
# vnd.docker.reference.type and have platform "unknown/unknown". Surfacing them
# here is informational, but it is the first clue about where attestations live.
ATTEST_ENTRIES="$(
  regctl manifest get "$HUB_REPO@$INDEX_DIGEST" --format body 2>/dev/null \
    | jq -c '[ (.manifests // [])[]
               | select((.annotations // {})["vnd.docker.reference.type"] != null)
               | { digest, referenceType: .annotations["vnd.docker.reference.type"],
                   referenceDigest: .annotations["vnd.docker.reference.digest"] } ]' \
    2>/dev/null || echo '[]'
)"
if [[ "$(jq -r 'length' <<<"$ATTEST_ENTRIES")" != "0" ]]; then
  log "note: index contains $(jq -r 'length' <<<"$ATTEST_ENTRIES") in-index attestation entrie(s) (BuildKit style)"
fi

# The gates inspect a single platform, because attestations attach per-platform.
PLATFORM_DIGEST="$(resolve_platform_digest "$HUB_REF" "$VERIFY_PLATFORM")"
if [[ -n "$PLATFORM_DIGEST" ]]; then
  log "RESOLVED platform digest ($VERIFY_PLATFORM): $PLATFORM_DIGEST"
else
  warn "no manifest for $VERIFY_PLATFORM in this index."
  warn "the gates will fall back to the index digest, which may legitimately have"
  warn "no referrers of its own -- check 'make inspect' if verify reports nothing."
fi

# ---------------------------------------------------------------------------
# Run manifest
# ---------------------------------------------------------------------------
RUN_ID="${GITHUB_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
ACTOR="local"
RUN_URL="null"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  ACTOR="github-actions"
  RUN_URL="\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}\""
fi

jq -n \
  --arg runId "$RUN_ID" \
  --arg startedAt "$(_ts)" \
  --arg actor "$ACTOR" \
  --argjson runUrl "$RUN_URL" \
  --arg regctlVersion "$(regctl version --format '{{.VCSTag}}' 2>/dev/null || echo unknown)" \
  --arg sourceRegistry "docker.io" \
  --arg sourceRepository "$HUB_REPO" \
  --arg tag "$TAG" \
  --arg ref "$HUB_REF" \
  --arg digestRef "$HUB_REPO@$INDEX_DIGEST" \
  --arg indexDigest "$INDEX_DIGEST" \
  --arg mediaType "$MEDIA_TYPE" \
  --arg platform "$VERIFY_PLATFORM" \
  --arg platformDigest "$PLATFORM_DIGEST" \
  --argjson platformsAvailable "$PLATFORMS_JSON" \
  --argjson inIndexAttestations "$ATTEST_ENTRIES" \
  --arg scoutRegistry "$SCOUT_REGISTRY" \
  --arg scoutRef "$(scout_ref)" \
  --arg quarantineRepo "$(gar_repo_path quarantine)" \
  --arg quarantineTagRef "$(gar_ref quarantine)" \
  --arg prodRepo "$(gar_repo_path prod)" \
  --arg prodTagRef "$(gar_ref prod)" \
  '{
    schemaVersion: 1,
    run: {
      id: $runId, startedAt: $startedAt, actor: $actor, runUrl: $runUrl,
      toolVersions: { regctl: $regctlVersion }
    },
    source: {
      registry: $sourceRegistry,
      repository: $sourceRepository,
      tag: $tag,
      ref: $ref,
      digestRef: $digestRef,
      indexDigest: $indexDigest,
      mediaType: $mediaType,
      platform: $platform,
      platformDigest: (if $platformDigest == "" then null else $platformDigest end),
      platformsAvailable: $platformsAvailable,
      inIndexAttestations: $inIndexAttestations
    },
    attestationSource: {
      registry: $scoutRegistry,
      repository: ($scoutRef | sub("^[^/]+/"; "")),
      ref: $scoutRef
    },
    targets: {
      quarantine: { repo: $quarantineRepo, tagRef: $quarantineTagRef, digestRef: null },
      prod:       { repo: $prodRepo,       tagRef: $prodTagRef,       digestRef: null }
    },
    gates: { verify: null, scan: null },
    stages: {
      resolve:  { status: "pass", at: $startedAt },
      sync:     null,
      verify:   null,
      scan:     null,
      promote:  null,
      evidence: null
    }
  }' >"$RUN_MANIFEST"

log "wrote $RUN_MANIFEST"
summary "### Resolve"
summary ""
summary "| | |"
summary "|---|---|"
summary "| Source | \`$HUB_REF\` |"
summary "| Index digest | \`$INDEX_DIGEST\` |"
summary "| Platform digest (\`$VERIFY_PLATFORM\`) | \`${PLATFORM_DIGEST:-none}\` |"
summary "| Platforms | $(jq -r 'if length == 0 then "single-platform" else join(", ") end' <<<"$PLATFORMS_JSON") |"

step "00 resolve: OK"
