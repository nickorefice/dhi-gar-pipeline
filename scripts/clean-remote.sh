#!/usr/bin/env bash
#
# clean-remote.sh -- delete everything the pipeline pushed, so `terraform destroy`
# has nothing left to trip over.
#
# DESTRUCTIVE. Invoked only via `make clean-remote CONFIRM=yes`, which is where the
# confirmation gate lives. It lists what it is about to delete before deleting it,
# because a teardown script that silently empties the wrong project is worse than
# no teardown script.
#
# Scoped to the two GAR repositories and the evidence bucket named in config.env.
# It never touches anything else in the project.

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

need_tool gcloud jq
require_vars GCP_PROJECT_ID EVIDENCE_BUCKET

step "teardown target"
log "project        : $GCP_PROJECT_ID"
log "GAR location   : $GAR_LOCATION"
log "quarantine repo: $GAR_QUARANTINE_REPO"
log "prod repo      : $GAR_PROD_REPO"
log "evidence bucket: gs://$EVIDENCE_BUCKET"

# ---------------------------------------------------------------------------
# GAR images
#
# Deleting the images rather than the repositories: the repositories are
# Terraform-managed, so removing them here would leave state inconsistent and
# make `terraform destroy` fail on resources that no longer exist.
# ---------------------------------------------------------------------------
for repo in "$GAR_QUARANTINE_REPO" "$GAR_PROD_REPO"; do
  path="${GAR_HOST}/${GCP_PROJECT_ID}/${repo}"
  step "GAR: $repo"

  if ! images="$(gcloud artifacts docker images list "$path" \
                   --include-tags --format='value(package)' 2>/dev/null | sort -u)"; then
    warn "could not list $path (already gone, or no permission) -- skipping"
    continue
  fi

  if [[ -z "$images" ]]; then
    log "already empty"
    continue
  fi

  log "will delete:"
  printf '%s\n' "$images" | sed 's/^/    /' >&2

  while read -r img; do
    [[ -n "$img" ]] || continue
    log "deleting $img"
    gcloud artifacts docker images delete "$img" --delete-tags --quiet 2>&1 \
      | sed 's/^/    /' >&2 || warn "failed to delete $img"
  done <<<"$images"
done

# ---------------------------------------------------------------------------
# Evidence objects
#
# Objects only. The bucket itself is Terraform-managed, and it has versioning
# enabled -- so `gcloud storage rm --recursive` on the object prefix is what
# actually clears it, including noncurrent versions via --all-versions.
# ---------------------------------------------------------------------------
step "evidence bucket"
if gcloud storage ls "gs://$EVIDENCE_BUCKET" >/dev/null 2>&1; then
  n="$(gcloud storage ls --recursive "gs://$EVIDENCE_BUCKET/**" 2>/dev/null | wc -l || echo 0)"
  if [[ "$n" == "0" ]]; then
    log "already empty"
  else
    log "deleting $n object(s) including noncurrent versions"
    gcloud storage rm --recursive --all-versions "gs://$EVIDENCE_BUCKET/**" 2>&1 \
      | tail -3 | sed 's/^/    /' >&2 || warn "some objects may remain"
  fi
else
  warn "gs://$EVIDENCE_BUCKET not found -- already destroyed?"
fi

step "verifying"
for repo in "$GAR_QUARANTINE_REPO" "$GAR_PROD_REPO"; do
  path="${GAR_HOST}/${GCP_PROJECT_ID}/${repo}"
  left="$(gcloud artifacts docker images list "$path" --format='value(package)' 2>/dev/null | wc -l || echo '?')"
  log "$repo: $left image(s) remaining"
done
left="$(gcloud storage ls --recursive "gs://$EVIDENCE_BUCKET/**" 2>/dev/null | wc -l || echo 0)"
log "evidence bucket: $left object(s) remaining"

step "done"
log "next: make tf-destroy"
log "note: the Workload Identity Pool is SOFT-deleted for 30 days. Terraform"
log "removes it cleanly, but re-creating a pool with the same ID inside that"
log "window fails -- change wif_pool_id if you need to re-apply immediately."
