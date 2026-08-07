# DHI → GAR mirroring pipeline

Mirrors Docker Hardened Images from a Docker Hub organization into Google
Artifact Registry **with their signed attestations intact**, gates promotion on
those attestations plus a VEX-aware vulnerability scan, and exports an evidence
bundle for audit.

Proof of concept, but a working one: validated end to end against real DHI images
in a real GCP project, from a laptop and from GitHub Actions.

## Why this exists

DHI ships SBOM, SLSA provenance, VEX, and vulnerability attestations alongside
each image. They are bound to the image **digest** and stored as OCI 1.1 referrers
in a *separate* registry (`registry.scout.docker.com`) from the image itself.

A naive `docker pull` / `docker push` mirror silently drops all of it — measured,
not assumed:

| Copy method | Digest | Attestations surviving |
|---|---|---|
| `regctl image copy` (naive mirror) | preserved ✅ | **0** ❌ |
| `regctl image copy --referrers --referrers-src` | preserved ✅ | **15** ✅ |

Note that the digest survives the naive copy. "The digest matches" is *not*
evidence the proof came with it.

What arrives in your internal registry after a naive mirror is just bytes. Every
downstream compliance question — what's in it, who built it, is CVE-X actually
exploitable here — then has to be answered by re-scanning instead of by reading
the vendor's signed answer.

**The registry carries the proof; the evidence bucket carries the paperwork.**
GAR referrers are the source of truth. The GCS bundle is a derived convenience
copy for GRC consumption.

## Architecture

```
Docker Hub  nicksdemoorg/dhi-node:TAG        registry.scout.docker.com/nicksdemoorg/dhi-node
      │  (image: multi-platform index)             │  (attestations: OCI referrers,
      │                                            │   attached PER-PLATFORM)
      └──────────────────┬──────────────────────────┘
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
        gs://PROJECT-dhi-evidence/dhi-node/sha256:.../
                                     ← SBOMs, provenance, VEX, gate reports
```

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

Breaking any of these invalidates the attestations, which defeats the point.

1. **The image is never rebuilt or re-tagged into a new digest.** No `docker
   build`, no manifest rewriting. The pipeline validates and promotes; it never
   transforms.
2. **Every copy is digest-pinned.** Stage 00 resolves the tag once; stages 10–50
   read the digest from the run manifest and never re-resolve. A tag that moved
   mid-run would otherwise let the pipeline verify one image and promote another.
3. **Attestations move as OCI referrers**, never extract-and-reattach. Re-signing
   would substitute *our* attestation for the vendor's.
4. **No long-lived GCP credentials.** CI federates via GitHub OIDC; no
   service-account key exists to leak.
5. **Promotion requires both gates green**, verified against the digest being
   promoted. A failed gate leaves the image in quarantine and still writes
   evidence.

## What running this against real DHI taught us

Each of these invalidated an assumption the pipeline was originally built on.
Reproduce them yourself with `make inspect`.

**Attestations attach to per-platform manifest digests, not the index.** The index
digest returns **0** referrers; each platform digest returns 14–17. A pipeline
that resolves a tag to an index digest and asks for referrers there concludes the
image has none. Stage 20 queries both subjects and merges.

**Every DHI attestation has `artifactType: application/vnd.in-toto+json`.** Nothing
is distinguishable by `artifactType`; the type lives only in the
`in-toto.io/predicate-type` annotation, and the payload is an in-toto Statement
wrapping the real document. A scanner handed the wrapper applies no VEX and
reports success.

**OpenVEX is not on every tag.** Present on debian-based tags, absent on the
alpine ones sampled. Requiring it unconditionally fails every Alpine DHI image, so
VEX is *expected* (warn) by default and promoted to required per tag.

**Neither vulnerability attestation is a VEX substitute.** `in-toto/vulns/v0.2`
holds `{scanner, metadata}`; `scout/vulnerabilities/v0.1` holds a findings list
with no status or justification fields. Deriving VEX from them would invent
assessments the vendor never made.

**Scanners do not apply DHI's VEX as shipped — this one is load-bearing.** DHI
identifies VEX products by Debian **source** package PURL; Trivy and Grype match
the **binary** package they found:

```
DHI VEX :  pkg:deb/debian/glibc@2.41-12+deb13u3+dhi1?os_distro=trixie&os_name=debian&os_version=13
Trivy   :  pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6
Grype   :  pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6&upstream=glibc
```

Measured on `dhi-node:26-debian13`:

| | Trivy findings | Grype HIGH/CRIT |
|---|---|---|
| VEX as shipped | **12** | **6** (`ignoredMatches: 0`) |
| VEX normalised | **0** | **0** |

Every one of those 12 was a CVE Docker had already declared `not_affected`. The
scan ran, `--vex` was passed, no error appeared, and **nothing was suppressed** —
the failure mode is a missing *effect*, not a wrong number. `30-scan.sh` therefore
normalises VEX product identifiers before scanning (see [Making scanners actually
ingest the VEX](#making-scanners-actually-ingest-the-vex)), and warns loudly if
VEX suppresses nothing while findings remain.

**GAR supports the OCI referrers API natively** — no `sha256-<digest>` fallback
tags were created, so referrers round-trip through the real API.

## Making scanners actually ingest the VEX

`scripts/lib/vex-normalize.jq` re-expresses each VEX statement in the package
identifiers the scanner emits, using the source → binary mapping from Trivy's own
`--list-all-pkgs` inventory (`SrcName`). On a real DHI image:

```
scanner package inventory: 15 package(s)
vex.openvex.01.json: 14 statement(s) remapped, 0 unmatched
    CVE-2010-0928:  openssl -> libssl3t64, openssl-provider-legacy
    CVE-2026-5435:  glibc   -> libc6
    CVE-2026-27171: zlib    -> zlib1g
```

It handles one-source-to-many-binaries (`openssl` → 2 packages) and the epoch
mismatch (VEX writes `1:` inline; the scanner PURL carries `?epoch=1`).

**What it does not do.** Statuses, justifications and impact statements are copied
verbatim; only product identifiers are *added*, originals retained. A statement
whose version does not match an installed package is reported `unmatched` and
**not** applied — guessing there would fabricate a vendor assessment, which is
worse than applying no VEX. `tests/test-vex-normalize.sh` asserts all of this,
including that no CVE is invented or dropped.

With it in place, on `dhi-node:26-debian13` at all severities:

```
findings without VEX (baseline) : 12
suppressed by vendor VEX        : 12     each with the vendor's justification
findings gating the promotion   : 0
```

## Prerequisites

```bash
make tools      # Homebrew on macOS, release binaries on Linux
make versions
```

`regctl`, `regsync`, `trivy`, `grype`, `cosign`, `docker scout`, `gcloud`,
`terraform`, `gh`, `jq`.

## Setup

```bash
make config                          # creates config.env
$EDITOR config.env                   # GCP_PROJECT_ID, GITHUB_OWNER, DOCKERHUB_USERNAME
printf '%s' 'dckr_oat_...' > ../.secrets/dockerhub-pat && chmod 600 ../.secrets/dockerhub-pat
```

> **For an Organization Access Token the registry username is the ORG name**, not
> a personal handle. Authenticating as the user fails with a bare `unauthorized`
> that looks like a permissions problem.

Manual steps (they need your credentials or a browser):

1. A GCP project with `artifactregistry`, `iam`, `iamcredentials`, `sts` enabled.
2. `gcloud auth login` and `gcloud auth application-default login`.
3. A read-only Docker Hub OAT/PAT that can read the org's Hardened Images.
4. Confirm the DHI repo is mirrored: Hub UI → Hardened Images → Manage → Mirrored
   Images, or `docker dhi mirror list --org <org>`.

Then:

```bash
make tf-init tf-apply    # GAR repos, evidence bucket, WIF pool + provider, SA
make gh-vars             # Terraform outputs → GitHub Actions repo variables
gh secret set DOCKERHUB_USERNAME --body '<org>'
gh secret set DOCKERHUB_PAT      # value on stdin
```

## Running it

```bash
make inspect REPO=dhi-node TAG=26-debian13   # diagnostic: are attestations visible?
make all     REPO=dhi-node TAG=26-debian13   # full pipeline, stops at the first failed gate
```

> DHI publishes **no `latest` tag**. Use a real one — `regctl tag ls
> docker.io/<org>/dhi-node`.

Reports land in `out/<repo>/<tag>/`.

---

## 10-minute demo

Runs against real DHI. Nothing here is staged.

### 1. Show what a naive mirror costs (1 min)

```bash
make test        # 49 offline assertions, no credentials needed
```

`tests/test-referrers-copy.sh` reproduces the DHI split-registry topology on local
disk and proves a naive copy preserves the digest while dropping every
attestation — and that querying referrers without `--external` returns **0 with a
zero exit code**. Silent, not loud.

### 2. Trigger the pipeline (2 min)

```bash
gh workflow run sync-dhi.yaml -f repo=dhi-node -f tag=26-debian13 -f require_vex=true
gh run watch
```

Or locally: `make all REPO=dhi-node TAG=26-debian13`.

Watch the Actions UI: resolve → sync → **verify** → **scan** → promote → evidence.
No GCP key anywhere — the `Authenticate to GCP (WIF)` step exchanges a GitHub OIDC
token for a short-lived credential.

### 3. Attestations are present in GAR (2 min)

```bash
PD=$(regctl manifest head us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node:26-debian13 \
       --platform linux/amd64 --require-digest)
regctl artifact list us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node@$PD --format body \
  | jq -r '.manifests[] | .annotations["in-toto.io/predicate-type"]' | sort
```

15 attestations: SPDX, CycloneDX, Scout SBOM, SLSA provenance v0.2 + v1, SLSA
verification summary, Scout provenance, **OpenVEX**, in-toto vulns, Scout
vulnerabilities / secrets / virus / tests, DHI source + changelog.

Then confirm the digest never changed:

```bash
regctl manifest head docker.io/<org>/dhi-node:26-debian13 --require-digest
regctl manifest head us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node:26-debian13 --require-digest
```

### 4. Scout reads them out of GAR (1 min)

```bash
docker scout attest list --platform linux/amd64 \
  registry://us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node@$PD
```

Standard Docker tooling consuming the attestations from *your* registry — not
Docker Hub.

### 5. The evidence bucket — the "SharePoint" story (1 min)

```bash
gcloud storage ls gs://$PROJECT-dhi-evidence/dhi-node/$DIGEST/
```

19 objects: every attestation as a file, plus `verify-report.json`,
`scan-report.json`, and `manifest.json` indexing them. In production this is
SharePoint via Graph, same folder layout.

Say the quiet part: **these are derived copies.** Verification is only meaningful
against the registry referrers.

### 6. Negative test — the gate blocks a promotion (3 min)

Real DHI, real failure. Alpine DHI ships no OpenVEX, so with VEX required:

```bash
REQUIRE_VEX=1 make resolve sync verify REPO=dhi-node TAG=24-alpine
```

```
[FAIL] required attestations MISSING: ["vex"] -- found ["provenance","sbom"] across 14 referrers
ERROR verify gate failed -- image stays in quarantine, nothing promoted
```

Then prove it did not sneak through:

```bash
make promote REPO=dhi-node TAG=24-alpine      # refuses; exit 1
regctl manifest head us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node:24-alpine  # 404
```

For a scan-gate failure instead, `make demo-fail` scans with VEX suppressed so
un-VEXed HIGH/CRITICAL findings block promotion.

---

## Offline tests

```bash
make test    # 65 assertions, no network / registry / cloud credentials
make lint    # shellcheck -x
```

| Suite | Covers |
|---|---|
| `test-classify.sh` (26) | Attestation classification under both storage conventions, missing-VEX, zero-referrer, `REQUIRE_VEX` policy override |
| `test-referrers-copy.sh` (13) | Real `regctl` copies between `ocidir://` layouts: the silent `--external` failure, naive-copy attestation loss, native referrers at the target, payload-level type resolution |
| `test-gate-safety.sh` (10) | Every way a promotion must be refused — crashed gate, stale verdict, verdict recorded for a different digest |
| `test-vex-normalize.sh` (16) | Source→binary PURL remapping, one-to-many, epoch handling, version-mismatch refusal, and that no status/justification/CVE is ever altered |

`test-gate-safety.sh` exists because of a real bug: a scan stage died before
writing its result, the previous run's `pass` was still in the manifest, and the
pipeline promoted an image carrying a CRITICAL CVE with exit code 0. A crashing
gate was indistinguishable from a passing one. Gates now mark themselves `running`
before anything that can fail, an EXIT trap converts that to `error`, and verdicts
record the digest they apply to.

## Teardown

```bash
make clean                          # local out/ only
make clean-remote CONFIRM=yes       # delete GAR images + evidence objects
make tf-destroy                     # remove the infrastructure
```

The Workload Identity Pool is **soft-deleted for 30 days**. Terraform removes it
cleanly, but re-applying with the same `wif_pool_id` inside that window fails —
change the ID if you need to redeploy immediately.

## Adapting this for a customer

[docs/customer-adaptation.md](docs/customer-adaptation.md) — OAT rotation,
webhook-driven sync, SharePoint via Graph, VPC-SC and separate projects, FIPS tag
filtering, and what to expect from scanners until the OSV feed cutover improves
DHI support.
