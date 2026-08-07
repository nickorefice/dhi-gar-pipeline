#!/usr/bin/env bash
#
# check-current.sh -- which sync-config.json entries actually need a pipeline run?
#
# The scheduled trigger polls every 30 minutes. Running the full pipeline that
# often -- image pull, two scanners, promotion, evidence export -- would burn
# ~10 minutes of runner time per tag per tick for work that almost always
# concludes "nothing changed". This check is the short-circuit: two HEAD requests
# per tag (upstream digest, prod digest), a comparison, and a filtered list out.
# A quiet tick costs seconds, not minutes.
#
# A tag needs a sync when:
#   not-in-prod     the tag has never been promoted
#   upstream-moved  the upstream digest differs from what prod holds
#
# Prints a JSON array of stale entries on STDOUT (logs go to stderr, like every
# other script here). Exit codes:
#   0  check completed; stdout is authoritative
#   3  check completed BUT one or more upstream digests could not be resolved.
#      Stdout still carries whatever was determined. Deliberately non-zero: if
#      the Hub credential dies, every entry becomes unresolvable and a silent
#      exit 0 would read as "everything is current" forever -- a dead poll that
#      looks healthy is the worst failure mode a scheduled trigger can have.
#
#   ./scripts/check-current.sh
#   SYNC_CONFIG=... SKIP_LOGIN=1 ./scripts/check-current.sh

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool regctl jq
require_vars GCP_PROJECT_ID

CONFIG="${SYNC_CONFIG:-$REPO_ROOT/sync-config.json}"
[[ -f "$CONFIG" ]] || die "no sync config at $CONFIG"

if [[ "${SKIP_LOGIN:-0}" != "1" ]]; then
  login_dockerhub
  login_gar
else
  log "auth: SKIP_LOGIN=1, reusing existing credentials"
fi

TOTAL="$(jq -r '.tags | length' "$CONFIG")"
step "checking $TOTAL configured tag(s) against prod"

RESULTS='[]'
ERRORS=0

while IFS=$'\t' read -r repo tag require_vex; do
  [[ -n "$repo" ]] || continue
  # The ref builders in common.sh read these globals.
  REPO="$repo"
  TAG="$tag"

  src="$(regctl manifest head "$(hub_ref)" --require-digest 2>/dev/null || true)"
  if [[ -z "$src" ]]; then
    warn "$repo:$tag  could not resolve the UPSTREAM digest -- excluded from this run."
    warn "  transient network failure, a removed tag, or a dead Hub credential."
    ERRORS=$((ERRORS + 1))
    continue
  fi

  prod="$(regctl manifest head "$(gar_ref prod)" --require-digest 2>/dev/null || true)"
  if [[ -z "$prod" ]]; then
    reason="not-in-prod"
  elif [[ "$prod" != "$src" ]]; then
    reason="upstream-moved"
  else
    log "$repo:$tag  current ($src)"
    continue
  fi

  log "$repo:$tag  NEEDS SYNC  reason=$reason upstream=$src prod=${prod:-none}"
  RESULTS="$(jq -c \
    --arg r "$repo" --arg t "$tag" --argjson rv "$require_vex" \
    --arg reason "$reason" --arg src "$src" --arg prod "${prod:-}" \
    '. + [{repo: $r, tag: $t, requireVex: $rv, reason: $reason,
           srcDigest: $src, prodDigest: (if $prod == "" then null else $prod end)}]' \
    <<<"$RESULTS")"
done < <(jq -r '.tags[] | [.repo, .tag, (.requireVex // false)] | @tsv' "$CONFIG")

STALE="$(jq -r 'length' <<<"$RESULTS")"
SUFFIX=""
(( ERRORS > 0 )) && SUFFIX=" ($ERRORS unresolvable -- exiting non-zero so this is investigated)"
step "result: $STALE of $TOTAL tag(s) need a sync$SUFFIX"

printf '%s\n' "$RESULTS"
(( ERRORS == 0 )) || exit 3
