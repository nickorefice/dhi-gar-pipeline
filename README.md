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
                │  30 scan gate   │  docker-scout CVEs + DHI VEX; Rego policy;
                │                 │  scout compare
                └────────┬────────┘
                         │  both green (and only then)
                         ▼
        GAR  dhi-prod/dhi-node        ← image + referrers, same digest
                         │
                         ▼
        gs://PROJECT-dhi-evidence/dhi-node/sha256:.../
                                     ← SBOMs, provenance, VEX, gate reports
```

**Triggering (POC):** a daily scheduled poll. The plan job runs the pipeline
library's `check_current` — two HEAD requests per configured tag — and syncs only
tags whose upstream digest differs from prod, so an all-current day is a ~1-minute
no-op (`make poll` fires the same path by hand). A Docker Hub
webhook→`repository_dispatch` relay is **built and validated but not deployed**:
Docker Hub cannot call the GitHub API directly (no custom headers, fixed payload,
no query-param tokens), so event-driven triggering needs a public relay endpoint,
which this POC deliberately avoids. See [relay/README.md](relay/README.md) for the
runbook when minute-level latency matters.

**The pipeline lives in GitHub Actions YAML.** Each stage is a composite
action under `.github/actions/<stage>/` carrying its full bash body, and the
plumbing every stage shares — config, auth, run manifest, the gate lifecycle,
and the verify / check-current / gate-check bodies — is the library embedded
in `.github/actions/pipeline-env/action.yaml`. The offline tests extract and
source that same library text (`tests/extract-pipeline-lib.sh`), so what is
tested is what runs. Only the jq programs (`scripts/lib/*.jq`), the Rego
policies (`policy/*.rego`), and `attestation-types.json` remain on disk as
shared data files.

**The pipeline's own tools run from Docker Hardened Images.** CI does not
download regctl, docker-scout, cosign, or opa release binaries: the install-tools
action pulls DHI images and installs transparent `/usr/local/bin/<tool>` wrappers
that `docker run` them, so the tools that gate the images carry the same signed
provenance, SBOM, and VEX story as the images they gate. Swapping any of them to
the FIPS build is one input override (e.g. `scout-image: ...:1.23.1-fips`).

Two sources, deliberately named per tool rather than chained as a fallback:

| Tool | Image | Source |
|---|---|---|
| `regctl` | `dhi-regctl:0.11.5` | org mirror |
| `cosign` | `dhi-cosign:3.1.3` | org mirror |
| `docker-scout` | `dhi.io/scout-cli:1.23.1` | Docker's DHI registry |
| `opa` | `dhi.io/open-policy-agent:1.19.1` | Docker's DHI registry |
| `regsync` | upstream release binary | no DHI image exists (`dhi.io/regsync` 404s) |

The last two come from `dhi.io` because **the org does not mirror them** —
verified against the live registry, where `<org>/dhi-regctl` lists 72 tags while
`<org>/dhi-scout-cli` and `<org>/dhi-open-policy-agent` do not exist. They are
still DHI images with the same attestations, published with
`com.docker.dhi.entitlement=public`. To move them onto the mirror, run
`docker dhi mirror start scout-cli` (and `open-policy-agent`) for the org, then
pass `scout-image` / `opa-image`.

If an image cannot be pulled the install fails loudly. It deliberately does
**not** fall back — not to a GitHub release binary, and not from the mirror to
`dhi.io` — because silently changing supply chains is the exact class of failure
this pipeline exists to prevent.

`docker-scout`, not `docker scout`: the DHI image's entrypoint is the
`/docker-scout` binary, so it is installed as a standalone command rather than
into `~/.docker/cli-plugins`. There is no plugin to find, and every call site
invokes it by that name.

| Stage | Action | Does |
|---|---|---|
| 00 | `.github/actions/resolve` | Resolve tag → digest **once**; write the run manifest |
| 10 | `.github/actions/sync` | Copy image + referrers → `dhi-quarantine` |
| 20 | `.github/actions/verify` | **Gate:** attestations survived, digest unchanged |
| 30 | `.github/actions/scan` | **Gate:** `docker-scout cves` w/ VEX **and** `policy/*.rego`; `scout compare` |
| 40 | `.github/actions/promote` | Copy `dhi-quarantine` → `dhi-prod` |
| 50 | `.github/actions/export-evidence` | Write evidence bundle to GCS |
| — | `.github/actions/inspect-referrers` | Diagnostic: where are the attestations, really? (`inspect-referrers.yaml` workflow) |

## What gets mirrored: the allow list

[`sync-config.yaml`](sync-config.yaml) is the admin-edited allow list — the
only file that decides what is auto-ingested. Images map to tag lists;
everything not listed is denied. Settings inherit image → tag:

```yaml
images:
  - repo: dhi-python
    requireVex: true        # fail verify if OpenVEX is absent (tags may override)
    tags:
      - 3-debian            # plain string inherits the image defaults
      - tag: 3.13-debian
        hold: true          # THE QUARANTINE LIST: sync + gate, never promote
```

`hold` is enforced in the promote gate itself, not merely skipped in the
workflow — a re-run of the promote step alone cannot slip a held tag into
prod (`FORCE_PROMOTE=1 ALLOW_UNSAFE=1` is the only, recorded, override). Held
tags are polled against **quarantine**, their permitted home, so they stay
fresh for testing without re-syncing every tick.

[`STATUS.md`](STATUS.md) is the generated tracking view: for every allow-list
entry, the latest upstream digest, the exact digest prod serves (deploy by
it), the quarantine state, and a classification — `current` / `stale` /
`blocked` / `held-*` / `missing`. CI regenerates it after every sync and poll
run and commits it only when it changed, so its git history is a free audit
trail of every digest movement; `make status` refreshes it on demand. It is a
derived view: the registry remains authoritative.

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
   promoted — and stage 30 is itself two independent refusals (vulnerabilities
   and Rego policy), either of which blocks. A failed gate leaves the image in
   quarantine and still writes evidence.
6. **A gate that could not run has approved nothing.** Undocumented scanner exit
   codes, an unobtainable SBOM, and a crashed stage are all recorded as `error`,
   never as a pass. "The scanner broke" and "the image is clean" must never be
   the same outcome.

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

**Not every scanner applies DHI's VEX — and the failure is silent. This is why
the scanner choice is load-bearing.** DHI identifies VEX products primarily by
Debian **source** package PURL, and only the source PURL carries a version and
the `os_*` qualifiers. A scanner that matches on the **binary** package it found
therefore matches nothing:

```
DHI VEX :  pkg:deb/debian/glibc@2.41-12+deb13u3+dhi1?os_distro=trixie&os_name=debian&os_version=13
binary  :  pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6
```

Measured with Trivy on `dhi-node:26-debian13`: **12** findings with the VEX as
shipped, **0** after remapping the identifiers. Every one of those 12 was a CVE
Docker had already declared `not_affected`. The scan ran, `--vex` was passed, no
error appeared, and **nothing was suppressed** — the failure mode is a missing
*effect*, not a wrong number, which is the hardest kind to notice.

**`docker-scout` does not have this problem, which is why it is the scan gate.**
Its SBOM emits the source package as its own artifact *and* each binary package
carrying a `parent` pointer back to it:

```
{"name":"glibc","purl":"pkg:deb/debian/glibc@2.41-12+deb13u3?os_distro=trixie&os_name=debian&os_version=13"}
{"name":"libc6","purl":"pkg:deb/debian/libc6@...","parent":"pkg:deb/debian/glibc@2.41-12+deb13u3?os_distro=..."}
```

That source PURL is the same shape as the VEX product identifier, so both sides
of the match already exist and no remapping step is needed. Scout also reads the
VEX attestation off the registry itself — no `--vex-location`, no VEX Hub sync.
The pipeline previously carried `scripts/lib/vex-normalize.jq` to bridge the gap
for Trivy; **that file is deleted**, and the scan stage instead records how many
SBOM artifacts carry a `parent` link, so a future Scout release that stopped
emitting them would surface as a count dropping to zero rather than as VEX
quietly ceasing to suppress.

The gate still reports the contrast, computed by set difference between a pass
with the vendor's VEX rejected and the real one, and still warns loudly if VEX
suppresses nothing while findings remain.

**GAR supports the OCI referrers API natively** — no `sha256-<digest>` fallback
tags were created, so referrers round-trip through the real API.

## The scan gate: two refusals

Stage 30 blocks on either of two independent findings. Neither substitutes for
the other: a clean CVE list on an image that is not a DHI is not a pass, and a
genuine DHI carrying un-VEXed criticals is not either.

**1. Vulnerabilities** — `docker-scout cves --only-severity <SCAN_SEVERITY>`
against the digest, with the vendor's VEX applied automatically from the
attestation.

**2. Policy** — [`policy/dhi-provenance.rego`](policy/dhi-provenance.rego),
evaluated by the OPA embedded in `docker-scout`. It asserts the image really is a
Docker Hardened Image, via the `com.docker.dhi.name` / `com.docker.dhi.distro`
markers.

That policy is deliberately **not** a base-image allowlist, and the reason is
worth recording: **a DHI has no base image.** `dhi-node` is not built `FROM`
anything — its history contains no rootfs import, and it is assembled from
hardened `.deb` packages fetched from `dhi.io`. Its SLSA provenance lists exactly
two container dependencies, `dhi/build` (the build toolchain) and
`dhi/scout-sbom-indexer`, neither of which is a runtime base. So Scout's built-in
`approved-base-images` policy reports *No data* on every tag this pipeline syncs,
and a hand-written "some dependency starts with `dhi`" test would pass by
matching the build toolchain — green for a reason unrelated to what it claims to
check. `org.opencontainers.image.base.name` is no help either: BuildKit has never
populated it ([moby/buildkit#2756](https://github.com/moby/buildkit/issues/2756)),
and it is absent on every DHI image *and* on stock library images, so a gate
reading it fails closed on 100% of legitimate traffic.

The `com.docker.dhi.*` markers appear as both config labels and manifest
annotations, and because annotations live inside the digest-covered manifest
bytes, a digest-preserving copy provably cannot strip them. Note the marker value
is `dhi/node` — with a **slash**. The mirror repository is `<org>/dhi-node` with a
hyphen; gating on `dhi-` would reject every genuine DHI.

They are, however, vendor-asserted metadata rather than a cryptographic proof —
anyone can label an image `com.docker.dhi.name=dhi/node`. The policy is a policy
gate, not a trust root, which is why it runs *after* stage 20 establishes that the
signed attestations are present and bound to this digest.

**The verdict comes from the exit code, not from parsing a report** — the
opposite of the Trivy implementation, and a deliberate inversion.
`docker scout cves` has no `--format json`; its structured outputs are
SARIF/GitLab/SPDX, whose population Docker does not document. Exit codes *are*
specified, so they are the verdict — checked with a strict allowlist: **0 is the
only pass**, 2 is findings, and anything else is a tooling failure that blocks.
"Fail only on 2" would be a fail-open bug: `scout-cli#213` records a run that
detected vulnerabilities and exited **255**. `tests/test-scan-gate.sh` asserts
every one of those branches, including that a crashed gate leaves a non-passing
status in the run manifest rather than a stale pass.

A clean scan is also cross-checked against an independent SBOM package count,
because a clean scan of an empty inventory looks exactly like a clean scan of a
real image.

⚠️ **New egress dependency.** Scout's CVE matching is **server-side**: there is
no local vulnerability database and no offline mode. The gate needs
`api.dso.docker.com` reachable, and DHI VEX comes from
`registry.scout.docker.com`. Both must be on any egress allowlist. A Docker Scout
outage now blocks promotion rather than passing it — the correct direction to
fail, but a real availability trade the Trivy implementation did not carry.

## Prerequisites

```bash
make tools      # Homebrew on macOS, release binaries on Linux
make versions
```

`regctl`, `regsync`, `cosign`, `docker scout`, `opa`, `gcloud`, `terraform`,
`gh`, `jq`. (In CI, regctl / docker-scout / cosign / opa run from the org's
mirrored DHI images; `make tools` covers local use.) `opa` is needed only by
`tests/test-policy.sh`, which evaluates `policy/*.rego` offline — the scan gate
itself does not need it, because `docker-scout policy` embeds OPA. Both that test
and `tests/test-scan-gate.sh` skip cleanly when their tooling is absent, so
`make test` never requires the network.

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

The pipeline runs in GitHub Actions; the make targets are thin `gh workflow
run` triggers:

```bash
make inspect REPO=dhi-node TAG=26-debian13   # diagnostic: are attestations visible?
make run     REPO=dhi-node TAG=26-debian13   # full pipeline, stops at the first failed gate
make status                                  # refresh STATUS.md, the tracking dashboard
make watch                                   # follow the run
```

> DHI publishes **no `latest` tag**. Use a real one — `regctl tag ls
> docker.io/<org>/dhi-node`.

Reports are uploaded as workflow artifacts (`reports-<repo>-<tag>`) and
summarised on the run page.

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

(`make run REPO=dhi-node TAG=26-debian13` is the same trigger.) In production this
is triggered by a Docker Hub webhook rather than by hand — to show that path, post
a real Hub payload at the relay:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data @tests/fixtures/dockerhub-webhook.json "https://<relay>/hook/<SECRET>"
# {"status": "dispatched", "repo": "nicksdemoorg/dhi-node", "tag": "26-debian13"}
```

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
make run REPO=dhi-node TAG=24-alpine REQUIRE_VEX=1
gh run watch
```

The verify gate fails and the run stops before promote:

```
[FAIL] required attestations MISSING: ["vex"] -- found ["provenance","sbom"] across 14 referrers
ERROR verify gate failed -- image stays in quarantine, nothing promoted
```

Then prove it did not sneak through — and that a promote step re-run on its own
still refuses (the gate check reads recorded verdicts, not step ordering):

```bash
regctl manifest head us-central1-docker.pkg.dev/$PROJECT/dhi-prod/dhi-node:24-alpine  # 404
```

For a scan-gate failure instead, `make demo-fail` scans with VEX suppressed so
un-VEXed HIGH/CRITICAL findings block promotion.

---

## Offline tests

```bash
make test    # 105 assertions, no network / registry / cloud credentials
make lint    # shellcheck: remaining scripts, tests, and every run block in the action YAMLs
```

The suites test the code CI actually runs: `tests/extract-pipeline-lib.sh`
extracts the pipeline library out of
`.github/actions/pipeline-env/action.yaml` and the tests source that text
directly, so a change to the YAML is a change to what is under test.
`test-scan-gate.sh` extracts stage 30's run block the same way. The jq programs
(`scripts/lib/*.jq`) and the Rego policies (`policy/*.rego`) are tested as the
files CI invokes.

| Suite | Covers |
|---|---|
| `test-classify.sh` (26) | Attestation classification under both storage conventions, missing-VEX, zero-referrer, `REQUIRE_VEX` policy override |
| `test-referrers-copy.sh` (13) | Real `regctl` copies between `ocidir://` layouts: the silent `--external` failure, naive-copy attestation loss, native referrers at the target, payload-level type resolution |
| `test-gate-safety.sh` (12) | Every way a promotion must be refused — crashed gate, stale verdict, verdict recorded for a different digest, sync-config.yaml hold |
| `test-policy.sh` (15) | `policy/*.rego` evaluated offline by OPA: a genuine DHI passes from either marker carrier, every non-DHI shape is refused, an empty input fails closed, each failure reports exactly one violation, and `--policy-config` overrides actually take effect |
| `test-scan-gate.sh` (30) | The scan gate's control flow, using the run block extracted from the action YAML against a stubbed `docker-scout`: the exit-code allowlist (0 pass / 2 findings / **anything else blocks**), that either half alone refuses, that a zero-package SBOM is not evidence, that `skip-vex` really inverts the verdict, and that no failure path leaves a passing verdict in the run manifest |
| `test-expand-config.sh` (18) | sync-config.yaml expansion: requireVex/hold inheritance (including explicit tag-level `false` over image-level `true`), and that a config typo fails loudly rather than silently shrinking the allow list |
| `test-relay.sh` (20) | Runs the real webhook relay on loopback: secret-path auth, payload validation, repo allow-list, tag filtering, dedupe, and fail-closed misconfiguration |

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

## License

[Apache-2.0](LICENSE). This is **example code — a worked reference, not a product
to run in production as-is**. Use it to see every mechanism working and to avoid
re-discovering the findings above, then build the equivalent inside your own
environment and review processes; the design invariants are the parts worth
carrying into any reimplementation. POC trade-offs are deliberately left in and
catalogued in [docs/customer-adaptation.md](docs/customer-adaptation.md).
