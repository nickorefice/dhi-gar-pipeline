# ---------------------------------------------------------------------------
# What the pipeline service account may do.
#
# Every binding below is scoped to a specific resource, never to the project.
# roles/artifactregistry.writer at project level would let a compromised CI token
# push to every registry in the project; bound per-repository it can only reach
# these two. Two extra bindings is a cheap price for that.
#
# artifactregistry.writer (not admin) is sufficient and correct: it grants
# upload + download of artifacts, which covers pushing manifests, blobs, and the
# referrer manifests that carry the attestations. It cannot delete or reconfigure
# repositories -- the pipeline has no business doing either.
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository_iam_member" "pipeline_quarantine_writer" {
  project    = google_artifact_registry_repository.quarantine.project
  location   = google_artifact_registry_repository.quarantine.location
  repository = google_artifact_registry_repository.quarantine.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.pipeline.email}"
}

resource "google_artifact_registry_repository_iam_member" "pipeline_prod_writer" {
  project    = google_artifact_registry_repository.prod.project
  location   = google_artifact_registry_repository.prod.location
  repository = google_artifact_registry_repository.prod.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.pipeline.email}"
}

# objectAdmin on the bucket only -- create/read/delete objects, but no ability to
# reconfigure the bucket, change its retention, or turn versioning off.
resource "google_storage_bucket_iam_member" "pipeline_evidence_writer" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.pipeline.email}"
}

# ---------------------------------------------------------------------------
# Who may become the pipeline service account.
#
# Defence in depth, layer 2 of 2 (layer 1 is the provider's attribute_condition):
# only workflows running in this exact repository may impersonate it. The
# principalSet is scoped by attribute.repository, so a fork -- which GitHub gives
# a different `repository` claim -- cannot use it.
#
# Note this is attribute.repository, NOT attribute.repository_owner. Scoping to
# the owner would let any repo in the account impersonate the pipeline, including
# one created later by someone with lesser review requirements.
# ---------------------------------------------------------------------------
resource "google_service_account_iam_member" "pipeline_wif_user" {
  service_account_id = google_service_account.pipeline.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${local.github_repository}"
}
