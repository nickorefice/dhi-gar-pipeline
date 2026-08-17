# Docker Hub webhook → pipeline trigger

> **Status: built and validated, deliberately NOT deployed in this POC.**
> The full path was exercised against real infrastructure — a real Docker Hub
> payload posted at the relay produced a `204` from GitHub, a
> `repository_dispatch` run, and a green pipeline for `dhi-node:24-debian13`.
> The POC's operative trigger is instead the **daily scheduled poll** in
> `sync-dhi.yaml`: the pipeline library’s `check_current` compares upstream digests against
> prod and runs the pipeline only for tags that changed. That gives ~24h
> worst-case latency with **zero public surface and no new secrets**.
>
> Deploy this relay when (a) minute-level latency becomes part of the story, and
> (b) you have confirmed a *mirror sync* actually fires webhooks — see
> [Known limitations](#known-limitations). Everything below is the runbook for
> that moment.

Fires the sync pipeline within minutes of a new tag landing in the mirrored DHI
repository, instead of waiting for the scheduled poll.

```
Docker Hub mirror gets a new tag
  │  POST (unauthenticated JSON)
  ▼
Cloud Run relay  ──  authenticates by secret URL path
  │                  allow-lists the repo, filters the tag, dedupes
  │  POST /repos/{owner}/{repo}/dispatches   (holds a GitHub token)
  ▼
GitHub Actions  repository_dispatch: [dhi-tag-pushed]
  │
  ▼
00 resolve → 10 sync → 20 verify → 30 scan → 40 promote → 50 evidence
```

Validated end to end: a real Docker Hub payload posted at the relay produced
`204` from GitHub, a `repository_dispatch` run, and a green pipeline for
`dhi-node:24-debian13`.

## Why a relay is needed

Docker Hub webhooks POST a JSON body to a URL. They cannot send an
`Authorization` header, so they cannot call the GitHub API directly. Something has
to hold a credential and translate. That is all this is.

## The security problem, stated plainly

**Docker Hub sends no HMAC, no signature, and no secret header.** Confirmed against
the [current webhook docs](https://docs.docker.com/docker-hub/repos/manage/webhooks/):
the payload has `push_data`, `repository`, and a `callback_url` that is a legacy
field no longer supported. There is nothing to verify.

So the URL *is* the credential, and Cloud Run must allow unauthenticated
invocations because Docker Hub cannot do GCP IAM auth. Given that, the relay is
built so a leaked URL is a nuisance rather than a breach:

| Control | Effect |
|---|---|
| Long random secret in the path, compared with `hmac.compare_digest` | Guessing and timing attacks |
| `ALLOWED_REPOS` | A leaked URL cannot name an arbitrary image; only allow-listed Hub repos are accepted |
| `TAG_ALLOW` / `TAG_DENY` | Only tags you already sync can be triggered |
| Dedupe on `repo:tag:pushed_at` | Replaying a captured payload is a no-op |
| Workflow re-checks against `sync-config.yaml` | Even a compromised relay cannot make CI sync an unreviewed tag |

Worst case with the URL in hand: someone re-triggers a sync of a tag you already
sync, at a digest the gates still have to pass. Rotate by changing
`WEBHOOK_SECRET` and updating the URL in Docker Hub.

## Why the tag filter is not optional

DHI mirrors **all** tags by default, and `dhi-node` carries roughly **450**. One
upstream rebuild can deliver a burst of webhooks. Unfiltered, that is hundreds of
concurrent pipeline runs, each pulling an image and running two scanners.

`TAG_ALLOW` is **fail-closed**: empty means nothing is dispatched. A relay that
syncs nothing is a visible, harmless misconfiguration; one that syncs everything
is a self-inflicted outage that looks like the pipeline is broken.

## Deploy

Needs two APIs beyond what `make tf-apply` enables:

```bash
gcloud services enable run.googleapis.com secretmanager.googleapis.com --project "$PROJECT"
```

**1. A GitHub token for the relay.** Fine-grained PAT, `Contents: read and write`
on `dhi-gar-pipeline` **only** — that is the permission `repository_dispatch`
requires, and nothing more.

```bash
SECRET_PATH="$(openssl rand -hex 24)"        # the URL credential
printf '%s' 'github_pat_...' | gcloud secrets create dhi-relay-github-token --data-file=-
printf '%s' "$SECRET_PATH"   | gcloud secrets create dhi-relay-webhook-secret --data-file=-
```

**2. Deploy.**

```bash
cd relay
gcloud run deploy dhi-webhook-relay \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --service-account dhi-relay@"$PROJECT".iam.gserviceaccount.com \
  --set-secrets GITHUB_TOKEN=dhi-relay-github-token:latest,WEBHOOK_SECRET=dhi-relay-webhook-secret:latest \
  --set-env-vars GITHUB_REPOSITORY=nickorefice/dhi-gar-pipeline \
  --set-env-vars ALLOWED_REPOS=nicksdemoorg/dhi-node \
  --set-env-vars 'TAG_ALLOW=^2[0-9]-debian13$,^24-alpine$' \
  --set-env-vars 'TAG_DENY=-dev$' \
  --min-instances 0 --max-instances 3 --concurrency 10 --timeout 30s
```

`--min-instances 0` means a cold start on the first webhook after idle. Docker Hub
tolerates it; if delivery timeouts appear in the history, set it to 1.

Or use `terraform/relay.tf` with `-var deploy_relay=true`.

**3. Create the webhook in Docker Hub.** This cannot be automated with an
Organization Access Token — the Hub API rejects it with
`{"detail":"Cannot log into an organization account"}`, so an OAT cannot create
webhooks. Use the UI:

> Docker Hub → `nicksdemoorg/dhi-node` → **Webhooks** → name it `dhi-gar-pipeline`
> → destination URL → **Create**

```
https://dhi-webhook-relay-XXXXXX.us-central1.run.app/hook/<SECRET_PATH>
```

Docker Hub caps the URL at **255 characters**. A Cloud Run URL plus a 48-char hex
secret fits comfortably.

**4. Verify.** Docker Hub shows delivery history per webhook, including whether the
POST succeeded — check there first when a tag does not trigger a run.

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data @../tests/fixtures/dockerhub-webhook.json \
  "https://.../hook/$SECRET_PATH"
# {"status": "dispatched", "repo": "nicksdemoorg/dhi-node", "tag": "26-debian13"}
```

## Responses

| Code | Meaning |
|---|---|
| `202` | Dispatched; a pipeline run is starting |
| `200 {"status":"ignored"}` | Tag deliberately not synced. **Deliberately not an error** — a filtered tag is not a failed delivery, and marking it failed trains whoever reads the delivery history to ignore it |
| `200 {"status":"duplicate"}` | Already dispatched recently |
| `400` | Not a Docker Hub push payload |
| `403` | Repository not allow-listed |
| `404` | Wrong or missing secret path |
| `502` | GitHub rejected the dispatch — surfaced so Hub records a failure and it can be retried, rather than silently dropping a real new tag |

## Keep the cron either way

In this POC the daily poll IS the trigger. If you deploy the relay, the poll
demotes to a **reconciliation backstop** — do not remove it. Webhook deliveries
get dropped, relays get redeployed, and Docker Hub does not guarantee delivery.
A daily sweep over `sync-config.yaml` catches whatever the event stream missed;
`regsync check` suits the same role if you would rather reconcile declaratively.

## Known limitations

- **Dedupe is in-memory.** It does not survive a cold start and is not shared
  across instances. Acceptable because it is an optimisation, not a correctness
  mechanism: the pipeline is idempotent, so a duplicate dispatch re-verifies and
  re-promotes the same digest. Use Firestore if you want it durable.
- **No retry on GitHub 5xx.** The relay returns `502` and relies on Docker Hub
  retrying. If Hub does not retry, the daily cron catches it.
- **Whether a mirror sync fires a webhook is worth confirming in your own org.**
  The docs state mirrored DHI repos are ordinary Hub repositories supporting
  webhooks, and that mirrors continuously receive new tags. That implies a
  webhook per mirrored tag, but it is asserted from documentation here, not
  observed — the mirror had no new tag during this build. Watch the delivery
  history after the next upstream DHI release before retiring the cron.

## Sources

- [Docker Hub webhooks](https://docs.docker.com/docker-hub/repos/manage/webhooks/)
- [Mirror a Docker Hardened Image repository](https://docs.docker.com/dhi/how-to/mirror/)
