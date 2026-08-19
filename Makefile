# DHI -> GAR mirroring pipeline.
#
# THE PIPELINE ITSELF LIVES IN GITHUB ACTIONS YAML: each stage is a composite
# action under .github/actions/<stage>/, and the plumbing they share is the
# library embedded in .github/actions/pipeline-env/action.yaml. The pipeline
# targets here trigger those workflows via `gh workflow run`; they do not
# execute stages locally. What CAN run locally, with no credentials, is the
# offline test suite -- which extracts and sources the same library text CI
# runs (tests/extract-pipeline-lib.sh), plus shellcheck over every bash run
# block embedded in the action YAMLs (tests/lint-actions.sh).
#
#   make help

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# DHI publishes no "latest" tag, so default to a real one.
REPO ?= dhi-node
TAG  ?= 26-debian13
export REPO TAG

# Config is read for Make-level targets (clean-remote) that need the values.
-include config.env

TF := terraform -chdir=terraform

.PHONY: help
help: ## Show this help
	@printf 'DHI -> GAR mirroring pipeline\n\n'
	@printf 'Pipeline (runs in GitHub Actions; override with REPO=<repo> TAG=<tag>):\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | grep -E '^(run|poll|demo-fail|inspect|status|watch):' \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\nSetup / infrastructure:\n'
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | grep -vE '^(run|poll|demo-fail|inspect|status|watch):' \
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
tools: ## Install the local toolchain (macOS/Homebrew; CI installs via .github/actions/install-tools)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
	  command -v brew >/dev/null 2>&1 || { echo "Homebrew required on macOS: https://brew.sh"; exit 1; }; \
	  brew install regclient cosign jq gh opa || true; \
	  brew install --cask google-cloud-sdk || true; \
	  brew tap hashicorp/tap || true; \
	  brew install hashicorp/tap/terraform || true; \
	  echo "docker scout ships with Docker Desktop. The pipeline calls it as 'docker-scout'"; \
	  echo "(CI installs a wrapper around the dhi-scout-cli image); for local parity run:"; \
	  echo "  ln -sf ~/.docker/cli-plugins/docker-scout /usr/local/bin/docker-scout"; \
	else \
	  echo "CI installs pinned release binaries via .github/actions/install-tools."; \
	  echo "For local Linux test runs only regctl and jq are needed -- install from"; \
	  echo "https://github.com/regclient/regclient/releases (pins are in the action)."; \
	fi

.PHONY: versions
versions: ## Print installed tool versions
	@printf '%-14s %s\n' regctl   "$$(regctl version 2>/dev/null | awk '/VCSTag/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' regsync  "$$(regsync version 2>/dev/null | awk '/VCSTag/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' cosign   "$$(cosign version 2>/dev/null | awk '/GitVersion:/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' scout    "$$(docker-scout version 2>/dev/null | awk '/version:/{print $$2; exit}' || docker scout version 2>/dev/null | awk '/version:/{print $$2; exit}' || echo MISSING)"
	@printf '%-14s %s\n' opa      "$$(opa version 2>/dev/null | awk '/^Version:/{print $$2}' || echo MISSING)"
	@printf '%-14s %s\n' gcloud   "$$(gcloud version 2>/dev/null | awk '/Google Cloud SDK/{print $$4}' || echo MISSING)"
	@printf '%-14s %s\n' terraform "$$(terraform version -json 2>/dev/null | jq -r .terraform_version || echo MISSING)"
	@printf '%-14s %s\n' jq       "$$(jq --version 2>/dev/null || echo MISSING)"

.PHONY: test
test: ## Run offline tests (they source the library extracted from the action YAML; no credentials needed)
	@./tests/test-classify.sh
	@echo
	@./tests/test-referrers-copy.sh
	@echo
	@./tests/test-gate-safety.sh
	@echo
	@./tests/test-policy.sh
	@echo
	@./tests/test-scan-gate.sh
	@echo
	@./tests/test-expand-config.sh
	@echo
	@./tests/test-relay.sh

.PHONY: lint
lint: ## shellcheck the remaining scripts, the tests, and every run block embedded in the action YAMLs
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed -- skipping"; exit 0; }
	@shellcheck -x scripts/*.sh tests/*.sh && python3 -m py_compile relay/main.py && echo "shellcheck + python clean"
	@./tests/lint-actions.sh

# ---------------------------------------------------------------------------
# Pipeline (triggers GitHub Actions -- the stages themselves are the composite
# actions under .github/actions/)
# ---------------------------------------------------------------------------
.PHONY: run
run: ## Trigger the full pipeline for REPO/TAG (REQUIRE_VEX=1 to make OpenVEX mandatory)
	@gh workflow run sync-dhi.yaml -f repo=$(REPO) -f tag=$(TAG) \
	  -f require_vex=$(if $(filter 1 true yes,$(REQUIRE_VEX)),true,false)
	@echo "started -- follow with: make watch"

.PHONY: poll
poll: ## Trigger the scheduled-poll path by hand (checks every sync-config tag against prod)
	@gh workflow run sync-dhi.yaml -f poll=true
	@echo "started -- follow with: make watch"

.PHONY: demo-fail
demo-fail: ## Negative test: run the scan gate with VEX suppressed so promotion is blocked
	@gh workflow run sync-dhi.yaml -f repo=$(REPO) -f tag=$(TAG) -f skip_vex=true
	@echo "started -- the scan gate is EXPECTED to fail; follow with: make watch"

.PHONY: inspect
inspect: ## Diagnostic: where does DHI actually keep attestations, and of what type
	@gh workflow run inspect-referrers.yaml -f repo=$(REPO) -f tag=$(TAG)
	@echo "started -- follow with: make watch"

.PHONY: status
status: ## Regenerate STATUS.md (the tracking dashboard) in CI and commit it
	@gh workflow run status.yaml -f commit=true
	@echo "started -- follow with: make watch"

.PHONY: watch
watch: ## Watch the most recent workflow run
	@gh run watch

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
