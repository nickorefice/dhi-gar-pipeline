# shellcheck shell=bash
#
# common.sh -- shared plumbing for the DHI -> GAR mirroring pipeline.
#
# Sourced by every stage script (00..50). Provides config loading, logging,
# registry auth, reference builders, digest resolution, and the run manifest
# that carries the resolved digest between stages.
#
# THE CENTRAL INVARIANT: tag -> digest resolution happens exactly once, in
# 00-resolve.sh, and is written to the run manifest. Every later stage reads the
# digest from the manifest and never re-resolves from the tag. If a tag were
# re-resolved mid-run and had moved, the pipeline could verify one image and
# promote a different one -- precisely the failure this design forbids.

set -euo pipefail

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
# BASH_SOURCE[0] is scripts/lib/common.sh -> repo root is two levels up.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$(cd "$LIB_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"
CLASSIFY_JQ="$LIB_DIR/classify.jq"
ATTESTATION_TYPES="$REPO_ROOT/attestation-types.json"
export LIB_DIR SCRIPTS_DIR REPO_ROOT CLASSIFY_JQ ATTESTATION_TYPES

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
# All logging goes to stderr so a stage can still emit machine-readable JSON on
# stdout without the caller having to strip log lines out of it.
_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log()  { printf '%s  %s\n'       "$(_ts)" "$*" >&2; }
warn() { printf '%s  WARN  %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s  ERROR %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s  ===== %s =====\n' "$(_ts)" "$*" >&2; }

# ok/bad render per-check gate results so the logs read as a checklist.
ok()  { printf '%s  [PASS] %s\n' "$(_ts)" "$*" >&2; }
bad() { printf '%s  [FAIL] %s\n' "$(_ts)" "$*" >&2; }

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
# Precedence: exported environment > config.env > built-in default.
#
# The environment has to win, because the documented interface is
# `REPO=dhi-python TAG=3.13 ./scripts/00-resolve.sh` -- if sourcing config.env
# clobbered that, per-run overrides would silently do nothing. `set -a; source`
# does clobber, so any config key already non-empty in the environment is
# captured first and re-applied afterwards.
load_config() {
  local cfg="${CONFIG_ENV:-$REPO_ROOT/config.env}"

  if [[ -f "$cfg" ]]; then
    local saved key
    saved="$(mktemp)"
    while IFS= read -r key; do
      [[ -n "${!key:-}" ]] && printf '%s=%q\n' "$key" "${!key}" >>"$saved"
    done < <(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$cfg")

    # Each `source` gets its own line: a shellcheck directive binds to the next
    # command, so folding these onto `set -a; source ...` would attach the
    # disable to `set -a` and leave the source unchecked-but-still-warned.
    set -a
    # shellcheck disable=SC1090  # path is config-driven by design
    source "$cfg"
    # shellcheck disable=SC1090  # generated temp file
    source "$saved"
    set +a
    rm -f "$saved"
    log "config: loaded $cfg (environment overrides preserved)"
  else
    log "config: no config.env found (using environment only)"
  fi

  : "${DOCKERHUB_ORG:=nicksdemoorg}"
  : "${SCOUT_REGISTRY:=registry.scout.docker.com}"
  : "${GAR_LOCATION:=us-central1}"
  : "${GAR_QUARANTINE_REPO:=dhi-quarantine}"
  : "${GAR_PROD_REPO:=dhi-prod}"
  : "${VERIFY_PLATFORM:=linux/amd64}"
  : "${SCAN_SEVERITY:=HIGH,CRITICAL}"
  : "${REPO:=dhi-node}"
  : "${TAG:=latest}"
  : "${GITHUB_REPO:=dhi-gar-pipeline}"

  GAR_HOST="${GAR_LOCATION}-docker.pkg.dev"
  export DOCKERHUB_ORG SCOUT_REGISTRY GAR_LOCATION GAR_QUARANTINE_REPO \
         GAR_PROD_REPO VERIFY_PLATFORM SCAN_SEVERITY REPO TAG GAR_HOST GITHUB_REPO
}

require_vars() {
  local missing=() v
  for v in "$@"; do
    if [[ -z "${!v:-}" || "${!v:-}" == REPLACE_ME* ]]; then missing+=("$v"); fi
  done
  (( ${#missing[@]} == 0 )) \
    || die "missing/unset config: ${missing[*]} -- set in config.env (see config.env.example) or export"
}

need_tool() {
  local t missing=()
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  (( ${#missing[@]} == 0 )) || die "required tool(s) not on PATH: ${missing[*]} -- run 'make tools'"
}

# --------------------------------------------------------------------------
# Reference builders
#
# Everything downstream builds refs through these, so there is exactly one place
# a registry path can be wrong.
# --------------------------------------------------------------------------
hub_repo() { printf '%s/%s' "$DOCKERHUB_ORG" "$REPO"; }
hub_ref()  { printf 'docker.io/%s/%s:%s' "$DOCKERHUB_ORG" "$REPO" "$TAG"; }

# The attestation registry. DHI stores attestations here under a repo path that
# mirrors the Hub path; this is the --referrers-src / --external source.
scout_ref() { printf '%s/%s/%s' "$SCOUT_REGISTRY" "$DOCKERHUB_ORG" "$REPO"; }

gar_repo_path() { # $1 = quarantine|prod
  local gar_repo
  case "$1" in
    quarantine) gar_repo="$GAR_QUARANTINE_REPO" ;;
    prod)       gar_repo="$GAR_PROD_REPO" ;;
    *) die "gar_repo_path: expected 'quarantine' or 'prod', got '$1'" ;;
  esac
  require_vars GCP_PROJECT_ID
  printf '%s/%s/%s/%s' "$GAR_HOST" "$GCP_PROJECT_ID" "$gar_repo" "$REPO"
}

gar_ref()        { printf '%s:%s' "$(gar_repo_path "$1")" "$TAG"; }
gar_digest_ref() { printf '%s@%s' "$(gar_repo_path "$1")" "$2"; }

# --------------------------------------------------------------------------
# Registry auth
# --------------------------------------------------------------------------
# One Docker Hub PAT authenticates both docker.io and registry.scout.docker.com.
# regclient shares Docker's ~/.docker/config.json credential store, so a regctl
# login is also visible to `docker scout`.
login_dockerhub() {
  require_vars DOCKERHUB_USERNAME
  [[ -n "${DOCKERHUB_PAT:-}" ]] || die "DOCKERHUB_PAT is not set (export it; never commit it)"

  local host
  for host in docker.io "$SCOUT_REGISTRY"; do
    log "auth: regctl login $host as $DOCKERHUB_USERNAME"
    printf '%s' "$DOCKERHUB_PAT" \
      | regctl registry login "$host" -u "$DOCKERHUB_USERNAME" --pass-stdin \
      || die "login failed for $host -- for $SCOUT_REGISTRY confirm the PAT can read the org's Hardened Images"
  done
}

# GAR takes a short-lived OAuth token as the password, with the fixed username
# oauth2accesstoken. Two sources, in order:
#   GAR_ACCESS_TOKEN -- exported by CI from google-github-actions/auth (WIF); no key file.
#   gcloud           -- local developer credentials from `gcloud auth login`.
login_gar() {
  require_vars GCP_PROJECT_ID
  local token
  if [[ -n "${GAR_ACCESS_TOKEN:-}" ]]; then
    token="$GAR_ACCESS_TOKEN"
    log "auth: GAR token from GAR_ACCESS_TOKEN (Workload Identity Federation)"
  else
    need_tool gcloud
    log "auth: GAR token from 'gcloud auth print-access-token'"
    token="$(gcloud auth print-access-token 2>/dev/null)" \
      || die "could not mint a GCP access token -- run 'gcloud auth login' or set GAR_ACCESS_TOKEN"
  fi
  [[ -n "$token" ]] || die "GCP access token was empty"

  printf '%s' "$token" \
    | regctl registry login "$GAR_HOST" -u oauth2accesstoken --pass-stdin \
    || die "regctl login failed for $GAR_HOST"
}

# --------------------------------------------------------------------------
# Run directory + run manifest
# --------------------------------------------------------------------------
tag_slug() { printf '%s' "$TAG" | tr -c 'A-Za-z0-9._-' '_'; }

init_run_dir() {
  OUT_DIR="${OUT_DIR:-$REPO_ROOT/out}"
  RUN_DIR="${RUN_DIR:-$OUT_DIR/$REPO/$(tag_slug)}"
  RUN_MANIFEST="$RUN_DIR/run-manifest.json"
  mkdir -p "$RUN_DIR/attestations"
  export OUT_DIR RUN_DIR RUN_MANIFEST
}

# Read the manifest written by 00-resolve.sh and export the digests. Stages
# 10..50 call this instead of ever touching a tag.
load_manifest() {
  init_run_dir
  [[ -f "$RUN_MANIFEST" ]] \
    || die "run manifest not found at $RUN_MANIFEST -- run scripts/00-resolve.sh first"

  SOURCE_REF="$(jq -r '.source.ref' "$RUN_MANIFEST")"
  INDEX_DIGEST="$(jq -r '.source.indexDigest' "$RUN_MANIFEST")"
  PLATFORM_DIGEST="$(jq -r '.source.platformDigest // empty' "$RUN_MANIFEST")"
  RESOLVED_PLATFORM="$(jq -r '.source.platform // empty' "$RUN_MANIFEST")"
  SCOUT_SRC="$(jq -r '.attestationSource.ref' "$RUN_MANIFEST")"
  export SOURCE_REF INDEX_DIGEST PLATFORM_DIGEST RESOLVED_PLATFORM SCOUT_SRC

  [[ "$INDEX_DIGEST" == sha256:* ]] || die "run manifest has no valid source.indexDigest"
  log "manifest: $RUN_MANIFEST"
  log "manifest: source          $SOURCE_REF"
  log "manifest: index digest    $INDEX_DIGEST"
  log "manifest: platform digest ${PLATFORM_DIGEST:-<none>} (${RESOLVED_PLATFORM:-n/a})"
}

# Atomically apply a jq filter to the run manifest.
# Usage: manifest_set '.gates.verify = $v' --argjson v "$json"
manifest_set() {
  local filter="$1"; shift
  local tmp; tmp="$(mktemp)"
  jq "$@" "$filter" "$RUN_MANIFEST" >"$tmp" && mv "$tmp" "$RUN_MANIFEST"
}

# --------------------------------------------------------------------------
# Digest resolution
# --------------------------------------------------------------------------
# `manifest head` is a HEAD request: it returns the digest without transferring
# the manifest body. --require-digest falls back to a GET when the registry
# omits the Docker-Content-Digest header.
resolve_index_digest() {
  local ref="$1"
  regctl manifest head "$ref" --require-digest \
    || die "could not resolve digest for $ref -- check the tag exists and that you are logged in"
}

# Returns empty (not an error) for single-platform images, which is a valid shape
# the gates must tolerate rather than crash on.
resolve_platform_digest() {
  local ref="$1" platform="$2"
  regctl manifest head "$ref" --platform "$platform" --require-digest 2>/dev/null || true
}

# --------------------------------------------------------------------------
# Referrers + classification
# --------------------------------------------------------------------------
# Fetch the raw referrers index for a subject. $2 (optional) is an external
# referrers source -- required for Hub subjects, whose attestations live in
# registry.scout.docker.com rather than alongside the image.
#
# An empty referrers set is a legitimate answer (it means "no attestations"),
# and distinguishing it from a transport failure is the verify gate's job, so a
# non-zero regctl exit is surfaced rather than swallowed.
fetch_referrers() {
  local subject="$1" external="${2:-}"
  local -a args=("$subject" --format body)
  [[ -n "$external" ]] && args+=(--external "$external")
  regctl artifact list "${args[@]}"
}

# Referrers index (file) -> classified inventory. See scripts/lib/classify.jq.
# $2 (optional) is a {digest: predicateType} map from deep resolution.
classify_referrers() {
  local referrers_json="$1" deep="${2:-}"
  [[ -n "$deep" ]] || deep='{}'
  jq -f "$CLASSIFY_JQ" \
     --argjson types "$(cat "$ATTESTATION_TYPES")" \
     --argjson deep "$deep" \
     "$referrers_json"
}

# Determine a referrer's predicate type by looking INSIDE it.
#
# Necessary because a referrer may advertise nothing useful on its descriptor:
# artifactType application/vnd.in-toto+json with no annotations is a complete and
# valid way to attach SLSA provenance, and it is indistinguishable from an SBOM
# without opening it. Two payload shapes are handled:
#
#   1. in-toto Statement    -- .predicateType at the top level of the blob.
#   2. Docker/BuildKit      -- the referrer is a manifest whose LAYER annotations
#      attestation manifest    carry in-toto.io/predicate-type.
#
# Prints the predicate type, or nothing if it cannot be determined. Never fails
# the caller: an unresolvable referrer is a finding for the gate to report, not an
# error to crash on.
resolve_predicate_type() {
  local repo="$1" digest="$2" payload pt

  # Shape 1: the blob is the in-toto Statement itself.
  payload="$(regctl artifact get "$repo@$digest" 2>/dev/null || true)"
  if [[ -n "$payload" ]]; then
    pt="$(jq -r 'if type == "object" then (.predicateType // empty) else empty end' <<<"$payload" 2>/dev/null || true)"
    if [[ -n "$pt" ]]; then printf '%s' "$pt"; return 0; fi
  fi

  # Shape 2: predicate type is on the referrer manifest's layer annotations.
  pt="$(regctl manifest get "$repo@$digest" --format body 2>/dev/null \
        | jq -r '[ (.layers // [])[]
                   | (.annotations // {})["in-toto.io/predicate-type"] // empty ] | .[0] // empty' \
        2>/dev/null || true)"
  [[ -n "$pt" ]] && printf '%s' "$pt"
  return 0
}

# classify_referrers, then re-run it having opened anything whose type could not
# be read from its descriptor.
#
#   $1  referrers index file
#   $2  repo reference (no tag/digest) holding the referrer BLOBS -- the Scout
#       repo when referrers were queried with --external, the image's own repo
#       when they are native.
classify_referrers_deep() {
  local referrers_json="$1" blob_repo="$2"
  local shallow deep_map digest pt

  shallow="$(classify_referrers "$referrers_json")"
  deep_map='{}'

  while read -r digest; do
    [[ -n "$digest" ]] || continue
    pt="$(resolve_predicate_type "$blob_repo" "$digest")"
    if [[ -n "$pt" ]]; then
      deep_map="$(jq -c --arg d "$digest" --arg p "$pt" '. + {($d): $p}' <<<"$deep_map")"
      log "deep-resolved ${digest:0:19}... -> $pt"
    else
      warn "could not determine a predicate type for ${digest:0:19}... (opened it; found none)"
    fi
  done < <(jq -r '.artifacts[]
                  | select(.class == "attestation-manifest-generic" or .class == "unclassified")
                  | .digest' <<<"$shallow")

  if [[ "$deep_map" == '{}' ]]; then
    printf '%s' "$shallow"
  else
    classify_referrers "$referrers_json" "$deep_map"
  fi
}

# --------------------------------------------------------------------------
# GitHub Actions step summary
# --------------------------------------------------------------------------
# No-ops outside CI so stage scripts can call it unconditionally.
summary() {
  [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] || return 0
  printf '%s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
}

# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------
load_config
