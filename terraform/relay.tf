# Cloud Run relay for the Docker Hub webhook.
#
# OPT-IN: everything here is gated on var.deploy_relay (default false), because it
# needs two APIs the rest of this stack does not (run, secretmanager) and would
# otherwise break `terraform apply` on a project where they are not enabled.
#
#   terraform apply -var deploy_relay=true
#
# The container image must exist before this applies -- build it with
# `gcloud run deploy --source relay/` once, or push relay/Dockerfile to GAR and set
# var.relay_image. Terraform manages the service, identity and secret wiring; it
# does not build images.

resource "google_service_account" "relay" {
  count        = var.deploy_relay ? 1 : 0
  account_id   = "dhi-relay"
  display_name = "DHI webhook relay"
  description  = "Runs the Docker Hub webhook relay. Reads two secrets; touches nothing else."
}

# ---------------------------------------------------------------------------
# Secrets
#
# The GitHub token and the webhook URL secret. Values are NOT managed here -- adding
# them to Terraform would put both in state. Create them with `gcloud secrets
# versions add` and let Terraform manage only the containers and access.
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "relay_github_token" {
  count     = var.deploy_relay ? 1 : 0
  secret_id = "dhi-relay-github-token"
  labels    = var.labels
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "relay_webhook_secret" {
  count     = var.deploy_relay ? 1 : 0
  secret_id = "dhi-relay-webhook-secret"
  labels    = var.labels
  replication {
    auto {}
  }
}

# accessor, not admin: the relay reads its own secrets and cannot modify or list others.
resource "google_secret_manager_secret_iam_member" "relay_github_token" {
  count     = var.deploy_relay ? 1 : 0
  secret_id = google_secret_manager_secret.relay_github_token[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.relay[0].email}"
}

resource "google_secret_manager_secret_iam_member" "relay_webhook_secret" {
  count     = var.deploy_relay ? 1 : 0
  secret_id = google_secret_manager_secret.relay_webhook_secret[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.relay[0].email}"
}

# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "relay" {
  count               = var.deploy_relay ? 1 : 0
  name                = "dhi-webhook-relay"
  location            = var.gar_location
  deletion_protection = false
  labels              = var.labels

  # Only Docker Hub calls this, from the public internet. It cannot present a GCP
  # identity, so IAM cannot be the gate -- the secret URL path is (see relay/README.md).
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account                  = google_service_account.relay[0].email
    timeout                          = "30s"
    max_instance_request_concurrency = 10

    scaling {
      # 0 accepts a cold start on the first webhook after idle; Docker Hub tolerates
      # it. Capped low because each dispatch starts a pipeline run -- an unbounded
      # relay in front of CI turns a webhook burst into a runner shortage.
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = var.relay_image

      env {
        name  = "GITHUB_REPOSITORY"
        value = local.github_repository
      }
      env {
        name  = "ALLOWED_REPOS"
        value = "${var.dockerhub_org}/${var.relay_allowed_repo}"
      }
      env {
        name  = "TAG_ALLOW"
        value = var.relay_tag_allow
      }
      env {
        name  = "TAG_DENY"
        value = var.relay_tag_deny
      }
      env {
        name = "GITHUB_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.relay_github_token[0].secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.relay_webhook_secret[0].secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = { cpu = "1", memory = "256Mi" }
      }

      startup_probe {
        http_get { path = "/healthz" }
        initial_delay_seconds = 2
        period_seconds        = 3
        failure_threshold     = 5
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.relay_github_token,
    google_secret_manager_secret_iam_member.relay_webhook_secret,
  ]
}

# Docker Hub is anonymous; without this the webhook gets 403 from Cloud Run before
# reaching the relay's own secret-path check.
resource "google_cloud_run_v2_service_iam_member" "relay_public" {
  count    = var.deploy_relay ? 1 : 0
  name     = google_cloud_run_v2_service.relay[0].name
  location = google_cloud_run_v2_service.relay[0].location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "relay_url" {
  description = "Relay base URL. The Docker Hub webhook destination is <this>/hook/<WEBHOOK_SECRET>."
  value       = var.deploy_relay ? google_cloud_run_v2_service.relay[0].uri : null
}
