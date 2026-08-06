locals {
  evidence_bucket = var.evidence_bucket_name != "" ? var.evidence_bucket_name : "${var.project_id}-dhi-evidence"

  # The exact repository allowed to impersonate the pipeline service account.
  github_repository = "${var.github_owner}/${var.github_repo}"
}

# ---------------------------------------------------------------------------
# Artifact Registry
#
# Two repositories, because quarantine is a trust boundary rather than a naming
# convention. An image lands in quarantine, the gates inspect it there, and only
# a passing image is copied to prod. Nothing pushes to prod directly.
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "quarantine" {
  repository_id = var.quarantine_repo_id
  location      = var.gar_location
  format        = "DOCKER"
  description   = "DHI images freshly synced from Docker Hub, pending attestation + scan gates. Not for deployment."
  labels        = var.labels

  docker_config {
    # Tags must stay mutable: the pipeline writes the human-readable tag
    # alongside the digest, and re-running a sync for a moved upstream tag has to
    # be able to update it. Immutability here would break re-runs without adding
    # safety, because every operation that matters is already digest-pinned.
    immutable_tags = false
  }
}

resource "google_artifact_registry_repository" "prod" {
  repository_id = var.prod_repo_id
  location      = var.gar_location
  format        = "DOCKER"
  description   = "DHI images that passed attestation verification and VEX-aware scanning. Deployable."
  labels        = var.labels

  docker_config {
    immutable_tags = false
  }
}

# ---------------------------------------------------------------------------
# Evidence bucket
#
# Stands in for the customer's SharePoint/GRC store. Holds DERIVED copies of the
# attestations plus the gate reports. The registry referrers remain the source of
# truth -- verification against this bucket proves nothing about the image.
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "evidence" {
  name     = local.evidence_bucket
  location = var.gar_location
  labels   = var.labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Evidence must never be silently overwritten -- a re-run that produces a
  # different report for the same digest is itself a finding worth keeping.
  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = var.evidence_noncurrent_versions_to_keep
    }
    action {
      type = "Delete"
    }
  }

  # POC affordance so `terraform destroy` is not blocked by objects the pipeline
  # wrote. A real GRC store would set this false and apply a retention policy --
  # audit evidence you can delete by running terraform is not audit evidence.
  force_destroy = true
}

# ---------------------------------------------------------------------------
# Pipeline identity
# ---------------------------------------------------------------------------
resource "google_service_account" "pipeline" {
  account_id   = var.service_account_id
  display_name = "DHI -> GAR mirroring pipeline"
  description  = "Impersonated by GitHub Actions via Workload Identity Federation. Has no keys."
}

# ---------------------------------------------------------------------------
# Workload Identity Federation
#
# This is what makes hard rule #4 achievable: GitHub Actions presents its OIDC
# token, GCP exchanges it for a short-lived credential. No service-account key
# exists, so there is none to leak, rotate, or find in a repo.
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = var.wif_pool_id
  display_name              = "DHI pipeline GitHub pool"
  description               = "Federates GitHub Actions OIDC tokens for the DHI mirroring pipeline."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.wif_provider_id
  display_name                       = "GitHub Actions OIDC"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
  }

  # Defence in depth, layer 1 of 2: reject the token exchange itself unless the
  # assertion comes from this exact repository. Without this, ANY GitHub repo on
  # the internet can mint a credential from this pool -- it is then only the IAM
  # binding standing between a stranger's workflow and your registry. Both layers
  # are cheap; relying on either alone is how these get quietly over-permissioned.
  attribute_condition = "assertion.repository == \"${local.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"

    # allowed_audiences is deliberately omitted. With it unset, GCP accepts only
    # one audience -- this provider's own resource URL -- which is precisely what
    # google-github-actions/auth requests by default. Setting it explicitly buys
    # no additional restriction and adds a way for the token exchange to fail on
    # a string mismatch nobody can see from the error message.
  }
}
