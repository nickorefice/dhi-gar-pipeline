variable "project_id" {
  description = "GCP project ID hosting the GAR repositories, evidence bucket, and WIF pool."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID (6-30 chars, lowercase letters/digits/hyphens, starting with a letter)."
  }
}

variable "gar_location" {
  description = "Artifact Registry / bucket location."
  type        = string
  default     = "us-central1"
}

variable "quarantine_repo_id" {
  description = "GAR repository receiving freshly synced images, before the gates run."
  type        = string
  default     = "dhi-quarantine"
}

variable "prod_repo_id" {
  description = "GAR repository images are promoted into once both gates pass."
  type        = string
  default     = "dhi-prod"
}

variable "evidence_bucket_name" {
  description = "Evidence bucket name. Defaults to <project_id>-dhi-evidence."
  type        = string
  default     = ""
}

variable "github_owner" {
  description = "GitHub account or org that owns the pipeline repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", var.github_owner))
    error_message = "github_owner must be a valid GitHub account/org name."
  }
}

variable "github_repo" {
  description = "Repository name. Combined with github_owner to restrict which repo may impersonate the pipeline service account."
  type        = string
  default     = "dhi-gar-pipeline"
}

variable "service_account_id" {
  description = "Account ID (local part) of the pipeline service account."
  type        = string
  default     = "dhi-pipeline"
}

variable "wif_pool_id" {
  description = "Workload Identity Pool ID."
  type        = string
  default     = "dhi-github-pool"
}

variable "wif_provider_id" {
  description = "Workload Identity Pool Provider ID for GitHub Actions OIDC."
  type        = string
  default     = "github-actions"
}

variable "evidence_noncurrent_versions_to_keep" {
  description = <<-EOT
    How many superseded versions of an evidence object to retain. Versioning is
    on because evidence must not be silently overwritten, but unbounded versions
    on a demo bucket is a slow cost leak, so old ones age out.
  EOT
  type        = number
  default     = 3
}

variable "labels" {
  description = "Labels applied to every resource that supports them."
  type        = map(string)
  default = {
    project    = "dhi-gar-pipeline"
    managed-by = "terraform"
    purpose    = "poc"
  }
}

# ---------------------------------------------------------------------------
# Webhook relay (see relay/README.md). Opt-in: needs run.googleapis.com and
# secretmanager.googleapis.com, which the rest of this stack does not use.
# ---------------------------------------------------------------------------
variable "deploy_relay" {
  description = "Deploy the Cloud Run webhook relay. Requires run + secretmanager APIs and a pre-built image."
  type        = bool
  default     = false
}

variable "relay_image" {
  description = "Container image for the relay. Build it once with `gcloud run deploy --source relay/`, or push relay/Dockerfile to GAR."
  type        = string
  default     = "us-central1-docker.pkg.dev/PROJECT/dhi-prod/dhi-webhook-relay:latest"
}

variable "dockerhub_org" {
  description = "Docker Hub organization holding the mirrored DHI repositories."
  type        = string
  default     = "nicksdemoorg"
}

variable "relay_allowed_repo" {
  description = "Repository name (without org) the relay will accept webhooks for. A leaked relay URL cannot name any other image."
  type        = string
  default     = "dhi-node"
}

variable "relay_tag_allow" {
  description = <<-EOT
    Comma-separated regexes a tag must match before the relay dispatches.

    FAIL-CLOSED: empty means nothing is dispatched. DHI mirrors all tags by default
    and dhi-node carries ~450, so an unfiltered relay turns one upstream rebuild
    into hundreds of concurrent pipeline runs.
  EOT
  type        = string
  default     = "^2[0-9]-debian13$,^24-alpine$"
}

variable "relay_tag_deny" {
  description = "Comma-separated regexes that reject a tag, applied after the allow list. -dev images ship a shell and package manager."
  type        = string
  default     = "-dev$"
}
