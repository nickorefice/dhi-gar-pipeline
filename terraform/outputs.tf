# These outputs are the handoff to CI. `make gh-vars` reads them and writes the
# corresponding GitHub Actions repository variables, so the workflow never has a
# project ID or provider path hardcoded in YAML.
#
# Note what is NOT here: any credential. The WIF provider name and service
# account email are both non-secret identifiers -- they are useless without a
# GitHub OIDC token from the one repository allowed to present one. That is the
# whole point of federation, and it is why these are repo *variables* rather than
# repo *secrets*.

output "project_id" {
  description = "GCP project ID."
  value       = var.project_id
}

output "gar_host" {
  description = "Artifact Registry host for docker/regctl login."
  value       = "${var.gar_location}-docker.pkg.dev"
}

output "gar_quarantine_repo" {
  description = "Fully qualified quarantine repository path (without image name)."
  value       = "${var.gar_location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.quarantine.repository_id}"
}

output "gar_prod_repo" {
  description = "Fully qualified prod repository path (without image name)."
  value       = "${var.gar_location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.prod.repository_id}"
}

output "evidence_bucket" {
  description = "Evidence bucket name (no gs:// prefix)."
  value       = google_storage_bucket.evidence.name
}

output "evidence_bucket_url" {
  description = "Evidence bucket URL."
  value       = "gs://${google_storage_bucket.evidence.name}"
}

output "pipeline_service_account" {
  description = "Service account the GitHub Actions workflow impersonates."
  value       = google_service_account.pipeline.email
}

output "workload_identity_provider" {
  description = "Full provider resource name for google-github-actions/auth's workload_identity_provider input."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "workload_identity_pool" {
  description = "Workload identity pool resource name."
  value       = google_iam_workload_identity_pool.github.name
}

output "authorized_github_repository" {
  description = "The only repository permitted to impersonate the pipeline service account."
  value       = local.github_repository
}
