#!/usr/bin/env bash
#
# set-gh-vars.sh -- push Terraform outputs into GitHub Actions repository variables.
#
# These are VARIABLES, not secrets, and that is deliberate. A WIF provider path and
# a service-account email are non-secret identifiers: they are useless without an
# OIDC token from the one repository the provider's attribute_condition accepts.
# Filing them as secrets would imply the security model rests on their secrecy,
# which it does not -- it rests on the federation binding.
#
# The only real secret in this pipeline is the Docker Hub credential, set
# separately with `gh secret set`.
#
# Standalone operator utility: runs on a laptop against local Terraform state,
# so it deliberately does NOT depend on the pipeline library embedded in
# .github/actions/pipeline-env/action.yaml.
#
#   ./scripts/set-gh-vars.sh

set -euo pipefail

# --- minimal standalone prelude (mirrors the pipeline library's semantics) ---
_ts()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { printf '%s  %s\n'       "$(_ts)" "$*" >&2; }
warn() { printf '%s  WARN  %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s  ERROR %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s  ===== %s =====\n' "$(_ts)" "$*" >&2; }

need_tool() {
  local t missing=()
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  (( ${#missing[@]} == 0 )) || die "required tool(s) not on PATH: ${missing[*]}"
}

require_vars() {
  local missing=() v
  for v in "$@"; do
    if [[ -z "${!v:-}" || "${!v:-}" == REPLACE_ME* ]]; then missing+=("$v"); fi
  done
  (( ${#missing[@]} == 0 )) \
    || die "missing/unset config: ${missing[*]} -- set in config.env (see config.env.example) or export"
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Environment beats config.env, same as the pipeline: capture already-set keys
# first and re-apply them after sourcing.
if [[ -f "$REPO_ROOT/config.env" ]]; then
  saved="$(mktemp)"
  while IFS= read -r key; do
    [[ -n "${!key:-}" ]] && printf '%s=%q\n' "$key" "${!key}" >>"$saved"
  done < <(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$REPO_ROOT/config.env")
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/config.env"
  # shellcheck disable=SC1090
  source "$saved"
  set +a
  rm -f "$saved"
fi
: "${DOCKERHUB_ORG:=nicksdemoorg}"
: "${GAR_LOCATION:=us-central1}"
: "${GAR_QUARANTINE_REPO:=dhi-quarantine}"
: "${GAR_PROD_REPO:=dhi-prod}"
: "${GITHUB_REPO:=dhi-gar-pipeline}"
# --- end prelude ---

need_tool gh terraform jq
require_vars GITHUB_OWNER GITHUB_REPO

TF_DIR="$REPO_ROOT/terraform"
[[ -d "$TF_DIR" ]] || die "no terraform directory at $TF_DIR"

step "reading Terraform outputs"
OUT="$(terraform -chdir="$TF_DIR" output -json 2>/dev/null)" \
  || die "could not read Terraform outputs -- run 'make tf-apply' first"

get() { jq -r --arg k "$1" '.[$k].value // empty' <<<"$OUT"; }

REPO_SLUG="$GITHUB_OWNER/$GITHUB_REPO"
log "target repository: $REPO_SLUG"

gh repo view "$REPO_SLUG" >/dev/null 2>&1 \
  || die "cannot see $REPO_SLUG -- check 'gh auth status' and that the repo exists"

set_var() { # set_var <NAME> <value>
  local name="$1" value="$2"
  if [[ -z "$value" ]]; then
    warn "skipping $name (Terraform produced no value)"
    return 0
  fi
  # Explicit if/else, not `A && B || C`: with the chained form a failure in the
  # logging call would trigger the die branch and report a spurious failure for a
  # variable that was in fact set.
  if gh variable set "$name" --repo "$REPO_SLUG" --body "$value" >/dev/null; then
    log "  $name = $value"
  else
    die "failed to set variable $name"
  fi
}

step "setting repository variables"
set_var GCP_PROJECT_ID       "$(get project_id)"
set_var GAR_LOCATION         "$GAR_LOCATION"
set_var GAR_QUARANTINE_REPO  "$GAR_QUARANTINE_REPO"
set_var GAR_PROD_REPO        "$GAR_PROD_REPO"
set_var EVIDENCE_BUCKET      "$(get evidence_bucket)"
set_var DOCKERHUB_ORG        "$DOCKERHUB_ORG"
set_var WIF_PROVIDER         "$(get workload_identity_provider)"
set_var WIF_SERVICE_ACCOUNT  "$(get pipeline_service_account)"

step "done"
cat >&2 <<EOF

Still to set, once, by hand -- these are the actual secrets:

  gh secret set DOCKERHUB_USERNAME --repo $REPO_SLUG --body '$DOCKERHUB_ORG'
  gh secret set DOCKERHUB_PAT      --repo $REPO_SLUG   # reads the value from stdin

For an Organization Access Token (dckr_oat_...) the username is the ORGANISATION
name, not a personal handle. Authenticating as the user fails with a bare
"unauthorized" that looks like a permissions problem rather than a wrong username.

Confirm the WIF binding is scoped to exactly this repository:
  $(get authorized_github_repository)
EOF
