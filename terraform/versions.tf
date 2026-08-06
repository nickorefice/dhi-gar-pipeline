terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.14"
    }
  }

  # Local state, deliberately, for a POC: it keeps `terraform destroy` a
  # one-liner with nothing left behind, and there is no team to coordinate with.
  #
  # A real deployment must use a GCS backend with state locking -- local state in
  # a shared repo means concurrent applies silently clobber each other, and the
  # state file contains the WIF and service-account wiring. See
  # docs/customer-adaptation.md.
  #
  # backend "gcs" {
  #   bucket = "PROJECT_ID-tfstate"
  #   prefix = "dhi-gar-pipeline"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.gar_location
}
