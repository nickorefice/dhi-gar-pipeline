#!/usr/bin/env bash
#
# 90-inspect-referrers.sh -- diagnostic. Not part of the pipeline.
#
# Answers the question the rest of this repo depends on: where does DHI actually
# put attestations, and what artifactType / predicateType does each one carry?
#
# Run this once against a real mirrored DHI repo before trusting the verify gate.
# It probes every plausible location and prints raw truth, then shows how
# attestation-types.json classifies what it found -- so any "unclassified" row is
# an explicit signal to add a matcher rather than a silent gap in the gate.
#
#   REPO=dhi-node TAG=22 ./scripts/90-inspect-referrers.sh
#
# Env:
#   SKIP_LOGIN=1   reuse existing credentials in ~/.docker/config.json
#   DEEP=0         skip second-level manifest inspection

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool regctl jq
init_run_dir

INSPECT_DIR="$RUN_DIR/inspect"
mkdir -p "$INSPECT_DIR"

HUB_REF="$(hub_ref)"
SCOUT_SRC="$(scout_ref)"

step "Inspecting $HUB_REF"
log "attestation source: $SCOUT_SRC"

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_dockerhub
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

# ---------------------------------------------------------------------------
# 1. Digest resolution -- index vs per-platform
#
# This distinction matters: if attestations are attached to per-platform
# manifests rather than the index, querying referrers on the index digest
# returns nothing and the gate would wrongly conclude "no attestations".
# ---------------------------------------------------------------------------
step "1. Digests"
INDEX_DIGEST="$(resolve_index_digest "$HUB_REF")"
log "index digest             : $INDEX_DIGEST"

PLATFORM_DIGEST="$(resolve_platform_digest "$HUB_REF" "$VERIFY_PLATFORM")"
if [[ -n "$PLATFORM_DIGEST" ]]; then
  log "platform digest ($VERIFY_PLATFORM): $PLATFORM_DIGEST"
else
  warn "no platform digest for $VERIFY_PLATFORM -- single-platform image, or that platform is absent from the index"
fi

log "platforms in the index:"
regctl manifest get "$HUB_REF" --format body 2>/dev/null \
  | jq -r '(.manifests // [])[]
           | "  - " + ((.platform.os // "?") + "/" + (.platform.architecture // "?")
             + (if .platform.variant then "/" + .platform.variant else "" end))
             + "  " + .digest
             + (if .annotations["vnd.docker.reference.type"]
                then "   [reference.type=" + .annotations["vnd.docker.reference.type"] + "]"
                else "" end)' \
  || warn "could not read the index body"

# ---------------------------------------------------------------------------
# 2. Probe every plausible referrers location
#
# Four probes, because "the attestations are missing" has four different causes
# and they are worth distinguishing before touching the gate logic.
# ---------------------------------------------------------------------------
step "2. Referrers probes"

probe() { # probe <label> <subject-ref> [external-ref]
  local label="$1" subject="$2" external="${3:-}"
  local file="$INSPECT_DIR/referrers-${label}.json"
  local -a args=("$subject" --format body)
  [[ -n "$external" ]] && args+=(--external "$external")

  printf '\n--- probe: %s\n' "$label" >&2
  printf '    subject : %s\n' "$subject" >&2
  printf '    external: %s\n' "${external:-<none, same repo>}" >&2

  if regctl artifact list "${args[@]}" >"$file" 2>"$file.err"; then
    local n; n="$(jq -r '(.manifests // []) | length' "$file" 2>/dev/null || echo '?')"
    printf '    result  : %s referrer(s) -> %s\n' "$n" "${file#"$REPO_ROOT"/}" >&2
    if [[ "$n" != "0" && "$n" != "?" ]]; then
      jq -r '(.manifests // [])[]
             | "      * " + (.artifactType // "(no artifactType)")
               + "  " + (.digest[0:19]) + "..."
               + (if (.annotations // {})["in-toto.io/predicate-type"]
                  then "\n          predicate: " + .annotations["in-toto.io/predicate-type"]
                  else "" end)' "$file" >&2
    fi
  else
    printf '    result  : QUERY FAILED\n' >&2
    sed 's/^/      /' "$file.err" >&2
    printf '{"manifests":[]}' >"$file"
  fi
}

probe "index-external-scout"    "${HUB_REF%%:*}@$INDEX_DIGEST"    "$SCOUT_SRC"
probe "index-hub-native"        "${HUB_REF%%:*}@$INDEX_DIGEST"    ""
if [[ -n "$PLATFORM_DIGEST" ]]; then
  probe "platform-external-scout" "${HUB_REF%%:*}@$PLATFORM_DIGEST" "$SCOUT_SRC"
  probe "platform-hub-native"     "${HUB_REF%%:*}@$PLATFORM_DIGEST" ""
fi
# Ask the Scout registry about its own subject digest directly, in case its
# referrers API is authoritative there rather than via --external.
probe "scout-direct-index"      "$SCOUT_SRC@$INDEX_DIGEST"        ""

# ---------------------------------------------------------------------------
# 3. Deep inspection -- resolve generic attestation manifests one level down
#
# For BuildKit/Docker-style attestations the referrer descriptor is a generic
# manifest; the predicate type only appears on that manifest's LAYER
# annotations. Without this step such an attestation is indistinguishable from
# any other and the gate cannot tell an SBOM from provenance.
# ---------------------------------------------------------------------------
if [[ "${DEEP:-1}" == "1" ]]; then
  step "3. Deep inspection of generic attestation manifests"
  found_generic=0
  for f in "$INSPECT_DIR"/referrers-*.json; do
    [[ -f "$f" ]] || continue
    while read -r d at; do
      [[ -n "$d" ]] || continue
      found_generic=1
      printf '\n--- %s  (artifactType=%s)\n' "${d:0:23}..." "$at" >&2
      # The blob lives in whichever repo served the referrer; Scout is the
      # documented home for DHI attestations, so try it first, then Hub.
      for base in "$SCOUT_SRC" "${HUB_REF%%:*}"; do
        if regctl manifest get "$base@$d" --format body >"$INSPECT_DIR/deep-${d#sha256:}.json" 2>/dev/null; then
          printf '    resolved from: %s\n' "$base" >&2
          jq -r '"    mediaType: " + (.mediaType // "?"),
                 "    layers:",
                 ((.layers // [])[]
                   | "      - " + (.mediaType // "?")
                     + (if (.annotations // {})["in-toto.io/predicate-type"]
                        then "\n        predicate: " + .annotations["in-toto.io/predicate-type"]
                        else "" end)
                     + (if (.annotations // {})["org.opencontainers.image.title"]
                        then "\n        title:     " + .annotations["org.opencontainers.image.title"]
                        else "" end))' \
            "$INSPECT_DIR/deep-${d#sha256:}.json" >&2
          break
        fi
      done
    done < <(jq -r '(.manifests // [])[]
                    | select((.annotations // {})["in-toto.io/predicate-type"] == null)
                    | select((.artifactType // "") | test("in-toto|docker.attestation"))
                    | .digest + " " + (.artifactType // "?")' "$f" 2>/dev/null | sort -u)
  done
  (( found_generic )) || log "no generic attestation manifests needed deep inspection"
fi

# ---------------------------------------------------------------------------
# 4. How attestation-types.json classifies the richest probe
# ---------------------------------------------------------------------------
step "4. Classification of the best probe result"
best=""; best_n=0
for f in "$INSPECT_DIR"/referrers-*.json; do
  [[ -f "$f" ]] || continue
  n="$(jq -r '(.manifests // []) | length' "$f" 2>/dev/null || echo 0)"
  if (( n > best_n )); then best_n="$n"; best="$f"; fi
done

if [[ -z "$best" ]]; then
  warn "every probe returned zero referrers -- no attestations were found anywhere."
  warn "likely causes, in order: (a) the PAT cannot read $SCOUT_REGISTRY,"
  warn "(b) this repo is not actually a mirrored DHI repo, (c) attestations hang off"
  warn "a digest none of the probes used. Check 'docker dhi mirror list' output."
else
  log "richest probe: ${best#"$REPO_ROOT"/} ($best_n referrers)"
  classify_referrers "$best" >"$INSPECT_DIR/classified.json"
  jq -r '"  groups present : " + (.groupsPresent | join(", ") | if . == "" then "(none)" else . end),
         "  groups MISSING : " + (.groupsMissing | join(", ") | if . == "" then "(none)" else . end),
         "  unclassified   : " + (.unclassified | tostring),
         "",
         "  inventory:",
         (.artifacts[] | "    " + (.class | . + (" " * (32 - length))) + (.artifactType // .predicateType // "?"))' \
    "$INSPECT_DIR/classified.json" >&2

  if [[ "$(jq -r '.unclassified' "$INSPECT_DIR/classified.json")" != "0" ]]; then
    warn "some referrers are unclassified. Add their artifactType/predicateType to"
    warn "attestation-types.json so the verify gate can reason about them:"
    jq -r '.artifacts[] | select(.class == "unclassified")
           | "    artifactType=" + (.artifactType // "null")
             + " predicateType=" + (.predicateType // "null")' \
      "$INSPECT_DIR/classified.json" >&2
  fi
fi

# ---------------------------------------------------------------------------
# 5. Docker Scout cross-check (informational)
# ---------------------------------------------------------------------------
step "5. docker scout attest list (cross-check)"
if docker scout version >/dev/null 2>&1; then
  docker scout attest list --platform "$VERIFY_PLATFORM" "registry://${HUB_REF#docker.io/}" 2>&1 \
    | sed 's/^/    /' >&2 || warn "docker scout attest list failed -- informational only, not a gate"
else
  warn "docker scout not installed -- skipping cross-check"
fi

step "Done"
log "raw output: ${INSPECT_DIR#"$REPO_ROOT"/}/"
