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
#   ./scripts/set-gh-vars.sh

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

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
