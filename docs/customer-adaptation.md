# Adapting this POC for a real deployment

What changes between this proof of concept and a regulated enterprise running it
for real. Each section states what the POC does, what production needs, and why.

Findings marked **[observed]** were measured against `nicksdemoorg/dhi-node` on
2026-08-07, not assumed from documentation.

---

## 1. Credentials: PAT → Organization Access Token

**POC:** a Docker Hub token in a GitHub Actions secret.

**Production:** an **Organization Access Token (OAT)**, scoped read-only to the
mirrored DHI repositories, owned by the organisation rather than a person. A PAT
dies with the employee who created it; an OAT survives them and is auditable in
the org's token list.

**[observed] The OAT username is the ORGANISATION name, not a personal handle.**
Authenticating as the user produces a bare `unauthorized` from the registry that
looks exactly like a permissions problem. This cost real debugging time here:

```bash
# WRONG -- fails with "unauthorized", no indication the username is at fault
regctl registry login registry.scout.docker.com -u alice --pass-stdin

# RIGHT
regctl registry login registry.scout.docker.com -u myorg --pass-stdin
```

Rotate on the org's schedule. The GCP side needs no rotation at all — Workload
Identity Federation issues short-lived credentials per run, and there is no key.

---

## 2. Trigger: polling now, webhook when latency matters

**The POC runs on a daily digest-compare poll** (`scripts/check-current.sh` in the
plan job): zero public surface, no new secrets, and immune to the open question of
whether mirror syncs fire webhooks at all. The webhook relay is **built and
validated end to end but not deployed** — see [relay/README.md](../relay/README.md)
for the deployment runbook.

A webhook cannot reach GitHub Actions directly: Docker Hub lets you configure only
a destination URL (no `Authorization` header), GitHub removed query-param token
auth in 2021, and the `repository_dispatch` body shape is fixed. So event-driven
triggering always means hosting a relay that holds a GitHub credential. Switch to
it when a new DHI build sitting unmirrored for up to a day is unacceptable.

Three things about the webhook path worth knowing before you deploy it.

**[observed] Docker Hub sends no HMAC, signature, or secret header.** There is
nothing to verify, so the URL is the only credential, and Cloud Run must allow
unauthenticated invocations because Docker Hub cannot present a GCP identity. The
relay therefore constrains what a leaked URL can achieve: an allow-listed
repository, an allow-listed tag, dedupe on `repo:tag:pushed_at`, and the workflow
re-checking the request against `sync-config.json`. Worst case, someone with the URL
re-triggers a sync of a tag you already sync, at a digest the gates still must pass.

**[observed] The tag filter is load-bearing, not a nicety.** DHI mirrors **all**
tags by default and `dhi-node` carries ~450. One upstream rebuild can deliver a
burst of webhooks; unfiltered that is hundreds of concurrent pipeline runs, each
pulling an image and running two scanners. `TAG_ALLOW` is fail-closed — empty
dispatches nothing, because a relay that syncs nothing is a visible and harmless
misconfiguration while one that syncs everything is a self-inflicted CI outage.

**[observed] An Organization Access Token cannot create the webhook.** The Hub API
rejects it with `{"detail":"Cannot log into an organization account"}`, so webhook
creation is a UI step (or needs a personal token with admin on the repo). Plan for
it as a manual step in the runbook.

**Keep the cron.** Docker Hub does not guarantee delivery, relays get redeployed,
and deliveries get dropped. A daily sweep over `sync-config.json` catches what the
event stream missed. `regsync check` suits the same role declaratively.

One thing to verify in your own org before retiring the cron: that a **mirror sync**
actually fires a webhook. The docs state mirrored DHI repos are ordinary Hub
repositories supporting webhooks and that mirrors continuously receive new tags,
which implies one webhook per mirrored tag — but that is read from documentation,
not observed, because the mirror had no new tag during this build. Watch the
webhook delivery history after the next upstream DHI release.

---

## 3. Evidence store: GCS → SharePoint via Microsoft Graph

**POC:** `gs://PROJECT-dhi-evidence/<repo>/<digest>/`.

**Production:** the same folder structure in SharePoint, written with Microsoft
Graph. Only `50-export-evidence.sh` changes; the layout is deliberately identical
so the GRC team's tooling does not care which backend produced it.

```
PUT /sites/{site-id}/drives/{drive-id}/root:/DHI-Evidence/{repo}/{digest}/{file}:/content
```

Use client credentials with `Sites.Selected`, granted on the one document library.
`Files.ReadWrite.All` is the easy answer and grants far too much.

**Keep the disclaimer in `manifest.json`.** These files are derived copies. They
are not cryptographically bound to the image, and anyone can edit a file in
SharePoint. Verification is only meaningful against the registry referrers. An
auditor who believes the bucket is authoritative has been misled by the
architecture, not by the data.

---

## 4. One project → organisation policy, VPC-SC, separate projects

**POC:** one GCP project, local Terraform state.

**Production:**

| Concern | Change |
|---|---|
| State | GCS backend with locking. Local state in a shared repo means concurrent applies clobber each other, and the state file holds the WIF wiring. |
| Projects | Separate quarantine and prod projects, not just repositories. A project is a blast-radius boundary; a repository is a name. |
| VPC-SC | Both projects inside a service perimeter, with GAR and GCS as restricted services. This is usually what a healthcare or financial customer actually needs from "our registry is private". |
| Org policy | `constraints/iam.disableServiceAccountKeyCreation` — the pipeline already needs no keys, so enforce it. Also `constraints/gcp.resourceLocations` if data residency applies. |
| Runners | VPC-SC blocks GitHub-hosted runners. Use self-hosted runners inside the perimeter, or Cloud Build with a private pool. |
| Deletion | Drop `force_destroy` on the evidence bucket and apply a retention policy. Audit evidence that Terraform can delete is not audit evidence. |

WIF needs no change: the federation binding is already scoped to a single
repository, enforced twice (provider `attribute_condition` and the IAM
`principalSet`).

---

## 5. Tag selection, FIPS, and variant filtering

**[observed]** `dhi-node` alone carries roughly 450 tags. Mirroring by wildcard is
slow, expensive, and pulls in variants nobody vetted.

The DHI variant suffixes are meaningful:

| Suffix | Meaning | Mirror to prod? |
|---|---|---|
| *(none)* | runtime image, no shell, no package manager | **yes** |
| `-dev` | includes shell and package manager | **no** — build stages only |
| `-fips` | FIPS-validated crypto modules; carries a `docker.com/dhi/fips` attestation | yes, if in scope |
| `-sfw` / `-sfw-ent` | additional software variants | as required |

For a FIPS-only estate, filter to `-fips` and make the FIPS attestation a hard
gate — add `dhi-fips` to `requiredGroups` in `attestation-types.json`, which fails
verification for any image that does not carry it. Same mechanism as `REQUIRE_VEX`.

A `-dev` image reaching a production registry is worth an explicit deny rule
rather than trusting an allow-list to stay correct; `regsync.yaml` carries one.

---

## 6. Scanning: what to expect, and what is not GA

### GAR native scanning of DHI is not yet GA

Artifact Analysis does not currently provide full native scanning coverage for
Docker Hardened Images. **Pipeline-side scanning with VEX applied is the current
pattern** — which is what stage 30 does. The expected improvement is the OSV feed
cutover, which should broaden scanner ecosystem support for DHI's package
metadata. Re-evaluate when that lands; the goal is to delete stage 30's scanner
management, not to keep it forever.

### [observed] Neither scanner applies DHI's VEX as shipped

**This is the most consequential finding here.** Verify it in your own environment
before trusting any VEX-aware gate, including this one.

DHI identifies VEX products by Debian **source** package PURL. Trivy and Grype
match on the **binary** package they discovered:

```
DHI VEX :  pkg:deb/debian/glibc@2.41-12+deb13u3+dhi1?os_distro=trixie&os_name=debian&os_version=13
Trivy   :  pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6
Grype   :  pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6&upstream=glibc
```

Different package name (source vs binary) and different qualifiers. Measured on
`dhi-node:26-debian13`:

| | Trivy (all severities) | Grype (HIGH/CRIT) |
|---|---|---|
| VEX as shipped | 12 findings | 6, `ignoredMatches: 0` |
| VEX normalised | **0** | **0** |

All 12 were CVEs Docker had already declared `not_affected`. The scan ran, `--vex`
was passed, no error was raised, and **nothing was suppressed**. The failure mode
is a missing effect, not a wrong number — `0 suppressed` reads identically whether
VEX worked with nothing to do or was ignored entirely.

**Mitigation** (implemented in `scripts/lib/vex-normalize.jq`): remap each
statement's products to the scanner's own identifiers, using the source → binary
mapping in Trivy's `--list-all-pkgs` inventory (`SrcName`). Statuses and
justifications are copied verbatim; a statement whose version does not match an
installed package is reported unmatched and not applied.

**What to check before adopting any scanner as your gate:**

1. Scan a DHI image with and without its VEX. If the counts are identical and
   there were findings to suppress, the VEX is not being applied.
2. Check whether the scanner exposes the source → binary mapping at all (Trivy:
   `SrcName` via `--list-all-pkgs`; Grype: `artifact.upstreams`). Without it, no
   remapping is possible.
3. Re-test after any scanner upgrade. This is version-specific behaviour, and a
   scanner that starts honouring source PURLs makes the remapping redundant —
   harmless, since it is additive, but worth removing.

Also note the two scanners assign **different severities** to the same CVE:
`CVE-2026-5435` is MEDIUM to Trivy and HIGH to Grype. A severity-threshold gate is
therefore scanner-specific, which is a second reason Grype is report-only here.

### [observed] VEX is not present on every DHI tag

OpenVEX ships on debian-based tags and is **absent** on the alpine-based tags
sampled (`24-alpine`, `24-alpine-fips`, `24-alpine-sfw-ent-dev`).

Consequences:

- Requiring VEX unconditionally fails every Alpine DHI image, for a property of
  the upstream image the pipeline cannot fix. VEX is therefore an *expected*
  group (warn) by default, promoted to required per-tag via `requireVex` in
  `sync-config.json` or `REQUIRE_VEX=1`.
- Without VEX the scan runs unsuppressed, so an Alpine DHI image may report CVEs
  its vendor has already assessed as not affecting it.

Confirm current behaviour with `make inspect` before setting policy — this is
observed behaviour at a point in time, not a documented guarantee.

### Neither vulnerability attestation is a VEX substitute

**[observed]** `in-toto.io/attestation/vulns/v0.2` carries only
`{scanner, metadata}`. `scout.docker.com/vulnerabilities/v0.1` carries a findings
list with CVSS but **no status or justification fields**.

Do not derive VEX from them. A findings list says "this CVE matches this package";
VEX says "and it does not affect this image, because…". Manufacturing the second
from the first invents an assessment the vendor never made, and puts it in an
audit record.

---

## 7. Two structural facts that shape any implementation

**[observed] Attestations attach to per-platform manifest digests, not the index.**
Querying referrers on the index digest of a multi-platform DHI image returns
**zero**; each platform digest returns 14–17. Any tool that resolves a tag to an
index digest and asks for referrers there will conclude the image has no
attestations. `20-verify.sh` queries both subjects and merges.

**[observed] Every DHI attestation carries `artifactType:
application/vnd.in-toto+json`.** Nothing is distinguishable by `artifactType`; the
document type appears only in the `in-toto.io/predicate-type` annotation, and the
payload is an in-toto Statement wrapping the real document. A scanner handed the
Statement wrapper applies no VEX and reports success. Stage 30 unwraps
`.predicate` before passing VEX to Trivy.

---

## 8. Deployment: consume by digest

The pipeline writes both a tag and a digest reference. **Deploy the digest.**

```yaml
image: us-central1-docker.pkg.dev/PROJECT/dhi-prod/dhi-node@sha256:bf96f6c2ac65...
```

A tag can move; a digest cannot. Everything this pipeline verified — the
attestations, the scan result, the evidence bundle — is bound to that digest and
says nothing about whatever the tag points at next week.

Enforce it in-cluster with a Kyverno or Gatekeeper policy that rejects tag-based
image references, and a second that requires images to come from `dhi-prod`. Then
the quarantine boundary is enforced by the cluster rather than by convention.

---

## 9. What this POC deliberately does not do

- **No signature verification of the attestations themselves.** The pipeline
  checks that attestations are present, well-typed, and digest-bound. Verifying
  Docker's signatures over them with `cosign verify-attestation` and a trusted
  key/identity policy is the natural next gate, and belongs in stage 20.
- **No admission control.** Getting an image into `dhi-prod` does not stop anyone
  deploying something else. See section 8.
- **No multi-region replication** of the registry or evidence store.
- **No alerting.** A failed gate writes a report and fails the job; nobody is
  paged. Route the failure into the customer's existing channel.
