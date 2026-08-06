# DHI -> GAR mirroring pipeline: local targets mirroring each CI stage.
#
# Every pipeline target is a thin wrapper over scripts/NN-*.sh so that what runs
# on a laptop and what runs in GitHub Actions are the same code path. The only
# difference is how GCP credentials arrive: ADC locally, WIF in CI.
#
#   make help

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

REPO ?= dhi-node
TAG  ?= latest
export REPO TAG

# Config is read by the scripts themselves; these are only for Make-level targets
# (tf-*, gh-vars, clean-remote) that need the values before a script runs.
-include config.env

TF := terraform -chdir=terraform

# Pinned so a demo cannot drift under you mid-week.
REGCLIENT_VERSION ?= v0.11.5
TRIVY_VERSION     ?= 0.73.0
GRYPE_VERSION     ?= 0.116.1
COSIGN_VERSION    ?= v3.1.3
SCOUT_VERSION     ?= 1.24.0

.PHONY: help
help: ## Show this help
	@printf 'DHI -> GAR mirroring pipeline\n\n'
	@printf 'Pipeline (override with REPO=<repo> TAG=<tag>):\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | grep -E '^(resolve|sync|verify|scan|promote|evidence|all|inspect|demo-fail):' \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\nSetup / infrastructure:\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | grep -vE '^(resolve|sync|verify|scan|promote|evidence|all|inspect|demo-fail):' \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\nCurrent: REPO=%s TAG=%s PROJECT=%s\n' "$(REPO)" "$(TAG)" "$(or $(GCP_PROJECT_ID),<unset>)"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
.PHONY: config
config: ## Create config.env from the example
	@if [ -f config.env ]; then echo "config.env already exists -- not overwriting"; \
	else cp config.env.example config.env; echo "created config.env -- fill in GCP_PROJECT_ID, GITHUB_OWNER, DOCKERHUB_USERNAME"; fi

.PHONY: tools
tools: ## Install the toolchain (regctl, regsync, trivy, grype, cosign, docker-scout)
	@./scripts/install-tools.sh

.PHONY: versions
versions: ## Print installed tool versions
	@printf '%-14s %s\n' regctl   "$$(regctl version 2>/dev/null | awk '/VCSTag/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' regsync  "$$(regsync version 2>/dev/null | awk '/VCSTag/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' trivy    "$$(trivy --version 2>/dev/null | head -1 | awk '{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' grype    "$$(grype version 2>/dev/null | awk '/^Version:/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' cosign   "$$(cosign version 2>/dev/null | awk '/GitVersion:/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' scout    "$$(docker scout version 2>/dev/null | awk '/version:/{print $$2; exit}' || echo MISSING)"
	@printf '%-14s %s\n' gcloud   "$$(gcloud version 2>/dev/null | awk '/Google Cloud SDK/{print $$4}' || echo MISSING)"
	@printf '%-14s %s\n' terraform "$$(terraform version -json 2>/dev/null | jq -r .terraform_version || echo MISSING)"
	@printf '%-14s %s\n' jq       "$$(jq --version 2>/dev/null || echo MISSING)"

.PHONY: test
test: ## Run offline tests (classifier + referrers copy via ocidir; no credentials needed)
	@./tests/test-classify.sh
	@echo
	@./tests/test-referrers-copy.sh

.PHONY: lint
lint: ## shellcheck every script
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed -- skipping"; exit 0; }
	@shellcheck -x scripts/*.sh scripts/lib/common.sh tests/*.sh && echo "shellcheck clean"

# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------
.PHONY: resolve
resolve: ## 00 Resolve tag -> digest, write the run manifest
	@./scripts/00-resolve.sh

.PHONY: sync
sync: ## 10 Copy image + referrers Hub -> GAR quarantine
	@./scripts/10-sync.sh

.PHONY: verify
verify: ## 20 Gate: attestations survived the copy, digest unchanged
	@./scripts/20-verify.sh

.PHONY: scan
scan: ## 30 Gate: Trivy (VEX-aware) + Grype + scout compare
	@./scripts/30-scan.sh

.PHONY: promote
promote: ## 40 Copy quarantine -> GAR prod (requires both gates green)
	@./scripts/40-promote.sh

.PHONY: evidence
evidence: ## 50 Export SBOM/VEX/provenance + reports to the evidence bucket
	@./scripts/50-export-evidence.sh

.PHONY: all
all: resolve sync verify scan promote evidence ## Full pipeline, stopping at the first failed gate

.PHONY: inspect
inspect: ## Diagnostic: where does DHI actually keep attestations, and of what type
	@./scripts/90-inspect-referrers.sh

.PHONY: demo-fail
demo-fail: ## Negative test: run the scan gate with VEX suppressed so promotion is blocked
	@./scripts/30-scan.sh --skip-vex

# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
.PHONY: tf-init
tf-init: ## terraform init
	@$(TF) init

.PHONY: tf-plan
tf-plan: ## terraform plan
	@$(TF) plan

.PHONY: tf-apply
tf-apply: ## terraform apply
	@$(TF) apply

.PHONY: tf-output
tf-output: ## Show Terraform outputs the workflow needs
	@$(TF) output

.PHONY: gh-vars
gh-vars: ## Push Terraform outputs into GitHub Actions repo variables
	@./scripts/set-gh-vars.sh

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
.PHONY: clean
clean: ## Delete local run output (out/)
	@rm -rf out && echo "removed out/"

.PHONY: clean-remote
clean-remote: ## Delete all images in both GAR repos and all evidence objects. CONFIRM=yes required
	@if [ "$(CONFIRM)" != "yes" ]; then \
	  echo "Refusing to delete remote data without CONFIRM=yes."; \
	  echo "This deletes every image in $(GAR_QUARANTINE_REPO) and $(GAR_PROD_REPO),"; \
	  echo "and every object in gs://$(EVIDENCE_BUCKET)."; \
	  echo "Re-run: make clean-remote CONFIRM=yes"; \
	  exit 1; \
	fi
	@./scripts/clean-remote.sh

.PHONY: tf-destroy
tf-destroy: ## terraform destroy (run clean-remote first)
	@$(TF) destroy
