#!/usr/bin/env bash
#
# install-tools.sh -- install the pipeline toolchain.
#
# Handles both hosts this POC runs on: a macOS laptop (Homebrew) and a Linux
# CI runner or container (release binaries). Versions are pinned so a demo
# cannot drift; override with e.g. TRIVY_VERSION=0.74.0.
#
# gcloud and terraform are installed only on macOS via Homebrew. On Linux the
# CI workflow provides them through their official setup actions, which is both
# faster and cached -- see .github/workflows/sync-dhi.yaml.

set -euo pipefail

REGCLIENT_VERSION="${REGCLIENT_VERSION:-v0.11.5}"
TRIVY_VERSION="${TRIVY_VERSION:-0.73.0}"
GRYPE_VERSION="${GRYPE_VERSION:-0.116.1}"
COSIGN_VERSION="${COSIGN_VERSION:-v3.1.3}"
SCOUT_VERSION="${SCOUT_VERSION:-1.24.0}"

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
log() { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH_GO=amd64; ARCH_TRIVY=64bit ;;
  arm64|aarch64) ARCH_GO=arm64; ARCH_TRIVY=ARM64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# --------------------------------------------------------------------------
# macOS: Homebrew handles everything, including gcloud and terraform.
# --------------------------------------------------------------------------
if [[ "$OS" == "Darwin" ]]; then
  command -v brew >/dev/null 2>&1 \
    || { echo "Homebrew required on macOS: https://brew.sh" >&2; exit 1; }
  log "installing via Homebrew"
  brew install regclient trivy grype cosign jq gh || true
  # regsync ships in the regclient formula alongside regctl.
  brew install --cask google-cloud-sdk || true
  brew tap hashicorp/tap || true
  brew install hashicorp/tap/terraform || true
  log "docker scout ships with Docker Desktop; 'docker scout version' should already work"
  exit 0
fi

# --------------------------------------------------------------------------
# Linux: release binaries.
# --------------------------------------------------------------------------
if [[ "$OS" != "Linux" ]]; then
  echo "unsupported OS: $OS" >&2; exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

install_bin() { # install_bin <src> <name>
  if [[ -w "$BIN_DIR" ]]; then install -m 0755 "$1" "$BIN_DIR/$2"
  else sudo install -m 0755 "$1" "$BIN_DIR/$2"; fi
  log "installed $2 -> $BIN_DIR/$2"
}

log "regclient $REGCLIENT_VERSION (regctl, regsync)"
for t in regctl regsync; do
  curl -fsSL -o "$t" \
    "https://github.com/regclient/regclient/releases/download/${REGCLIENT_VERSION}/${t}-linux-${ARCH_GO}"
  chmod +x "$t"; install_bin "$t" "$t"
done

log "trivy $TRIVY_VERSION"
curl -fsSL -o trivy.tgz \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH_TRIVY}.tar.gz"
tar xzf trivy.tgz trivy && install_bin trivy trivy

log "grype $GRYPE_VERSION"
curl -fsSL -o grype.tgz \
  "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH_GO}.tar.gz"
tar xzf grype.tgz grype && install_bin grype grype

log "cosign $COSIGN_VERSION"
curl -fsSL -o cosign \
  "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${ARCH_GO}"
chmod +x cosign && install_bin cosign cosign

log "docker scout $SCOUT_VERSION (CLI plugin)"
curl -fsSL -o scout.tgz \
  "https://github.com/docker/scout-cli/releases/download/v${SCOUT_VERSION}/docker-scout_${SCOUT_VERSION}_linux_${ARCH_GO}.tar.gz"
tar xzf scout.tgz docker-scout
mkdir -p "$HOME/.docker/cli-plugins"
install -m 0755 docker-scout "$HOME/.docker/cli-plugins/docker-scout"
log "installed docker-scout -> $HOME/.docker/cli-plugins/docker-scout"

log "done. gcloud and terraform are not installed here -- CI supplies them via"
log "google-github-actions/setup-gcloud and hashicorp/setup-terraform."
