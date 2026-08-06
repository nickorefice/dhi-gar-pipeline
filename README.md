# DHI → GAR mirroring pipeline

Mirrors Docker Hardened Images from a Docker Hub organization into Google
Artifact Registry **with their signed attestations intact**, gates promotion on
those attestations plus a VEX-aware vulnerability scan, and exports an evidence
bundle for audit.

> **Status:** proof of concept. See [Current status](#current-status).

## Why this exists

DHI ships SBOM, SLSA provenance, VEX, and vulnerability-report attestations
alongside each image. Those attestations are bound to the image **digest** and
stored as OCI 1.1 referrers in a *separate* registry
(`registry.scout.docker.com`) from the image itself.

A naive `docker pull` / `docker push` mirror silently drops all of it. What
arrives in your internal registry is then just bytes — you have the image but
none of the proof, so every downstream compliance question ("what's in it?",
"who built it?", "is CVE-X actually exploitable here?") has to be answered by
re-scanning instead of by reading the vendor's signed answer.

This pipeline preserves the referrers, then treats them as the gate.

**The registry carries the proof; the evidence bucket carries the paperwork.**
GAR referrers are the source of truth. The evidence bundle in GCS is a derived
convenience copy for GRC consumption — verification is only meaningful against
the registry.

## Architecture

```
Docker Hub  nicksdemoorg/dhi-node:TAG          registry.scout.docker.com/nicksdemoorg/dhi-node
      │  (image: multi-platform index)               │  (attestations: OCI referrers)
      └───────────────────┬───────────────────────────┘
                          │  regctl image copy --referrers --referrers-src
                          ▼
        GAR  dhi-quarantine/dhi-node   ← image + referrers, digest-pinned
                          │
                 ┌────────┴────────┐
                 │  20 verify gate │  attestations present? digest unchanged?
                 │  30 scan gate   │  Trivy + DHI VEX; Grype 2nd opinion; scout compare
                 └────────┬────────┘
                          │  both green (and only then)
                          ▼
        GAR  dhi-prod/dhi-node        ← image + referrers, same digest
                          │
                          ▼
        gs://PROJECT_ID-dhi-evidence/dhi-node/sha256:.../
                                      ← SBOM, provenance, VEX, gate reports
```

### Stages

| Stage | Script | Does |
|---|---|---|
| 00 | `00-resolve.sh` | Resolve tag → digest **once**; write the run manifest |
| 10 | `10-sync.sh` | Copy image + referrers → `dhi-quarantine` |
| 20 | `20-verify.sh` | **Gate:** attestations survived, digest unchanged |
| 30 | `30-scan.sh` | **Gate:** Trivy w/ VEX, Grype, `scout compare` |
| 40 | `40-promote.sh` | Copy `dhi-quarantine` → `dhi-prod` |
| 50 | `50-export-evidence.sh` | Write evidence bundle to GCS |
| — | `90-inspect-referrers.sh` | Diagnostic: where are the attestations, really? |

## Design invariants

These are load-bearing. Breaking any of them invalidates the attestations, which
defeats the entire point of the pipeline.

1. **The image is never rebuilt, re-tagged into a new digest, or otherwise
   mutated.** Attestations are bound to the digest; changing the digest orphans
   them. There is no `docker build` anywhere in this repo, and no manifest
   rewriting. The pipeline validates and promotes — it never transforms.
2. **Every copy is digest-pinned.** `00-resolve.sh` resolves tag → digest once
   and writes it to `out/<repo>/<tag>/run-manifest.json`. Stages 10–50 read the
   digest from that manifest and never re-resolve the tag. A tag that moves
   mid-run would otherwise let the pipeline verify one image and promote a
   different one.
3. **Attestations move as OCI referrers, never extract-and-reattach.**
   `regctl image copy --referrers` preserves them as-is. Re-signing or
   re-wrapping would substitute *our* attestation for the vendor's, discarding
   the provenance chain that makes it worth having.
4. **No long-lived GCP credentials.** CI authenticates via Workload Identity
   Federation from GitHub Actions OIDC — no service-account key exists to leak.
   Locally, `gcloud` user credentials (ADC).
5. **Promotion requires both gates green.** A failed gate leaves the image in
   quarantine and writes a failure report to the evidence bucket. Quarantine is
   not a staging area you promote out of by hand; it is where images that failed
   stay.

### A note on the digest the gates inspect

The *copy* always moves the full multi-platform index. The *gates* pin
`linux/amd64` (`VERIFY_PLATFORM`), because DHI attaches attestations to
per-platform manifests rather than to the index. Querying referrers on the index
digest alone can return nothing even when attestations are present — a failure
mode that looks identical to "the copy dropped them". `90-inspect-referrers.sh`
exists to tell those two apart.

## Prerequisites

| Tool | Purpose |
|---|---|
| `regctl`, `regsync` | registry copies incl. referrers — the core of the pipeline |
| `trivy` | VEX-aware vulnerability scan (the gate) |
| `grype` | second-opinion scan (report-only) |
| `cosign` | signature inspection |
| `docker scout` | `attest list` cross-check, `compare` for the diff view |
| `gcloud` | GCP auth, GAR/GCS access |
| `terraform` | provisions GAR repos, bucket, WIF |
| `gh` | sets repo variables from Terraform outputs |
| `jq` | report generation and referrer classification |

```bash
make tools      # Homebrew on macOS, release binaries on Linux
make versions   # confirm
```

## Setup

```bash
make config     # creates config.env from the example
$EDITOR config.env   # set GCP_PROJECT_ID, GITHUB_OWNER, DOCKERHUB_USERNAME
export DOCKERHUB_PAT='dckr_pat_...'   # never committed, never in config.env
```

Manual steps that are deliberately not automated (they need your credentials or
a browser):

1. **GCP project + APIs** — `artifactregistry`, `iam`, `iamcredentials`, `sts`.
2. **`gcloud auth login` and `gcloud auth application-default login`.**
3. **Docker Hub PAT (read-only)** → GitHub Actions secrets `DOCKERHUB_USERNAME`,
   `DOCKERHUB_PAT`. The same PAT must authenticate to both `docker.io` and
   `registry.scout.docker.com`. An Organization Access Token is the enterprise
   recommendation — see [docs/customer-adaptation.md](docs/customer-adaptation.md).
4. **Confirm the DHI repo is mirrored** into your org: Hub UI → Hardened Images
   → Manage → Mirrored Images, or `docker dhi mirror list --org <org>`.

Then:

```bash
make tf-init tf-apply    # GAR repos, evidence bucket, WIF pool + provider, SA
make gh-vars             # push Terraform outputs into GitHub Actions variables
```

## Running it

```bash
make inspect REPO=dhi-node TAG=22   # diagnostic: confirm attestations are visible
make all     REPO=dhi-node TAG=22   # full pipeline, stops at the first failed gate
```

Or stage by stage:

```bash
make resolve REPO=dhi-node TAG=22
make sync verify scan promote evidence REPO=dhi-node TAG=22
```

Reports land in `out/<repo>/<tag>/`: `run-manifest.json`, `verify-report.json`,
`scan-report.json`, plus extracted attestations under `attestations/`.

## Offline tests

```bash
make test    # 35 assertions, no network / registry / cloud credentials
make lint    # shellcheck -x
```

**`tests/test-classify.sh`** (22) exercises the attestation classifier — the logic
the verify gate's pass/fail rests on — against synthetic referrer indexes. The
fixtures cover *both* storage conventions DHI might use (`artifactType` carries
the type, vs. BuildKit-style predicate annotations), plus the missing-VEX and
zero-referrer failure cases.

**`tests/test-referrers-copy.sh`** (13) tests the referrers mechanics for real.
regctl talks to `ocidir://` OCI layouts through the same code path it uses for a
registry, so the DHI topology is reproduced on local disk — image in one repo,
attestations in another — and the actual copy is exercised. It pins down:

| Behaviour | Why it matters |
|---|---|
| Querying referrers without `--external` returns **0, and does not error** | The pipeline's central failure mode: a mirror that looks successful while dropping every attestation |
| Naive `image copy` → digest preserved, **0 attestations** | What a normal mirror does to DHI |
| `--referrers --referrers-src` → digest preserved, **3 attestations** | What this pipeline does instead |
| Attestations are **native** referrers at the target | GAR consumers need no `--external`, unlike the source |
| An annotation-free in-toto referrer needs its **payload opened** | Descriptor-only classification reports valid SLSA provenance as missing |

That last row is why `classify_referrers_deep` exists — see
[Deep classification](#deep-classification).

## Deep classification

A referrer can advertise nothing useful about itself. `artifactType:
application/vnd.in-toto+json` with no annotations at all is a valid way to attach
SLSA provenance, and it is indistinguishable from an SBOM without opening it.

So the verify gate resolves those by fetching the payload and reading
`.predicateType` from the in-toto Statement (or, for Docker/BuildKit attestation
manifests, the `in-toto.io/predicate-type` annotation on the manifest's layers).
Measured against a real referrer set:

```
shallow (descriptors only):  groupsMissing = ["provenance"]   -> gate FAILS on valid provenance
deep    (payload opened):    groupsMissing = []               -> gate correct
```

`verify-report.json` records `deepResolved: true` per artifact, so the report
shows *how* each claim was established rather than only that it was.

## Teardown

```bash
make clean                          # local out/ only
make clean-remote CONFIRM=yes       # delete GAR images + evidence objects
make tf-destroy                     # remove the infrastructure
```

## Current status

Built and validated offline:

- [x] Toolchain (regctl, regsync, trivy, grype, cosign, docker scout, shellcheck)
- [x] Shared library, config precedence, run-manifest contract
- [x] Attestation classifier + 22 passing unit tests, shellcheck clean
- [ ] Terraform (written; `apply` pending GCP credentials)
- [ ] Stage scripts 00–50
- [ ] CI workflow
- [ ] End-to-end run against real DHI attestations

`gcloud` and `terraform` are not yet installed in the dev sandbox — their
download hosts (`dl.google.com`, `releases.hashicorp.com`) are firewall-blocked.
