#!/usr/bin/env python3
"""
Docker Hub webhook -> GitHub repository_dispatch relay.

WHY A RELAY EXISTS AT ALL
Docker Hub webhooks POST an unauthenticated JSON body to a URL. They cannot send
an Authorization header, so they cannot call the GitHub API directly. Something
has to sit in between, hold a GitHub credential, and translate.

THE TWO THINGS THIS MUST GET RIGHT

1. Authentication, without any help from Docker Hub.
   Docker Hub sends no HMAC, no signature, and no secret header -- confirmed
   against the current docs. There is therefore nothing to verify, and the URL
   itself is the only credential available. Consequences, all handled below:
     - the secret lives in the path and is compared in constant time
     - the URL must stay within Docker Hub's 255-character limit
     - a leaked URL must not be able to do much, so the payload is additionally
       constrained to an allow-listed repository and tag. Possession of the URL
       lets someone re-trigger a sync of a tag we already sync; it does not let
       them choose an arbitrary image.

2. Not melting CI.
   DHI mirrors ALL tags by default, and dhi-node carries ~450 of them. One
   upstream rebuild can produce a burst of webhook deliveries. Without the tag
   allow-list below, that is hundreds of concurrent pipeline runs, each pulling
   an image and running two scanners. The filter is not a nicety.

Deliberately stdlib-only: no dependencies to audit, and it runs under a buildpack
or a three-line Dockerfile unchanged.

Environment:
  WEBHOOK_SECRET      required. The path segment that authenticates a request.
  GITHUB_TOKEN        required. Needs contents:write on the target repo only.
  GITHUB_REPOSITORY   required. "owner/repo" to dispatch to.
  ALLOWED_REPOS       comma-separated Hub repo names, e.g. "nicksdemoorg/dhi-node".
  TAG_ALLOW           comma-separated regexes a tag must match. Empty = allow none.
  TAG_DENY            comma-separated regexes that reject a tag. Applied after allow.
  DISPATCH_EVENT_TYPE defaults to "dhi-tag-pushed".
  PORT                provided by Cloud Run.
  DRY_RUN             "1" to log the dispatch without calling GitHub.
"""

import hmac
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("relay")

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
DISPATCH_EVENT_TYPE = os.environ.get("DISPATCH_EVENT_TYPE", "dhi-tag-pushed")
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
MAX_BODY = 256 * 1024

def _csv(name):
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]

ALLOWED_REPOS = set(_csv("ALLOWED_REPOS"))
TAG_ALLOW = [re.compile(p) for p in _csv("TAG_ALLOW")]
TAG_DENY = [re.compile(p) for p in _csv("TAG_DENY")]

# Docker Hub may deliver the same event more than once, and a mirror sync can
# push the same tag twice in quick succession. Dispatching twice would run the
# whole pipeline twice on an identical digest.
#
# In-memory, so it does not survive a cold start and does not dedupe across
# instances. That is acceptable because it is an optimisation, not a correctness
# mechanism: the pipeline is idempotent (same digest in, same digest promoted).
# Durable dedupe would need Firestore or Redis; see relay/README.md.
_SEEN = OrderedDict()
_SEEN_MAX = 512
_SEEN_TTL = 900


def already_seen(key):
    now = time.time()
    for k in [k for k, ts in _SEEN.items() if now - ts > _SEEN_TTL]:
        _SEEN.pop(k, None)
    if key in _SEEN:
        return True
    _SEEN[key] = now
    while len(_SEEN) > _SEEN_MAX:
        _SEEN.popitem(last=False)
    return False


def tag_allowed(tag):
    """Explicit allow-list. An empty TAG_ALLOW allows NOTHING.

    Fail-closed on purpose: a misconfigured relay that syncs no tags is a visible,
    harmless problem. One that syncs all 450 is a self-inflicted denial of service
    against your own CI, and it looks like the pipeline is broken rather than
    over-triggered.
    """
    if not any(p.search(tag) for p in TAG_ALLOW):
        return False, "no TAG_ALLOW pattern matched"
    for p in TAG_DENY:
        if p.search(tag):
            return False, f"matched TAG_DENY {p.pattern!r}"
    return True, ""


def dispatch(repo_name, tag, pushed_at, pusher):
    """POST a repository_dispatch to GitHub."""
    owner_repo = GITHUB_REPOSITORY
    payload = {
        "event_type": DISPATCH_EVENT_TYPE,
        "client_payload": {
            # Short names because GitHub caps client_payload at 10 top-level keys.
            "repo": repo_name.split("/", 1)[-1],
            "hub_repo": repo_name,
            "tag": tag,
            "pushed_at": pushed_at,
            "pusher": pusher,
            "source": "dockerhub-webhook",
        },
    }
    if DRY_RUN:
        LOG.info("DRY_RUN dispatch -> %s %s", owner_repo, json.dumps(payload))
        return 204, "dry-run"

    req = urllib.request.Request(
        f"https://api.github.com/repos/{owner_repo}/dispatches",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "dhi-gar-pipeline-relay/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:400]
    except Exception as e:  # noqa: BLE001 - report any transport failure verbatim
        return 0, f"{type(e).__name__}: {e}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "dhi-relay/1"

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Unauthenticated liveness only. Deliberately reveals nothing about
        # configuration -- an unauthenticated probe should not confirm which repos
        # or tags this relay will act on.
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        expected = f"/hook/{WEBHOOK_SECRET}"

        # Constant-time comparison. A timing side channel on a secret sitting in a
        # URL is a small risk, but it is free to eliminate.
        if not WEBHOOK_SECRET or not hmac.compare_digest(path, expected):
            LOG.warning("rejected: bad path (len=%d)", len(path))
            self._reply(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, {"error": "bad content-length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._reply(413, {"error": "empty or oversized body"})
            return

        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            LOG.warning("rejected: unparseable body: %s", e)
            self._reply(400, {"error": "invalid json"})
            return

        # Docker Hub payload shape (per docs): {push_data: {tag, pushed_at, pusher},
        # repository: {repo_name, ...}}. callback_url exists but is a legacy field
        # that is no longer supported, so it is ignored.
        push = body.get("push_data") or {}
        repo = body.get("repository") or {}
        tag = (push.get("tag") or "").strip()
        repo_name = (repo.get("repo_name") or "").strip()
        pushed_at = push.get("pushed_at")
        pusher = push.get("pusher") or ""

        if not tag or not repo_name:
            LOG.warning("rejected: missing push_data.tag or repository.repo_name")
            self._reply(400, {"error": "not a docker hub push payload"})
            return

        if ALLOWED_REPOS and repo_name not in ALLOWED_REPOS:
            LOG.warning("rejected: repo %s not allow-listed", repo_name)
            self._reply(403, {"error": "repository not allowed"})
            return

        ok, why = tag_allowed(tag)
        if not ok:
            # 200, not an error: Docker Hub's delivery history should show success.
            # A tag we intentionally do not sync is not a failed delivery, and
            # marking it failed would train whoever reads that history to ignore it.
            LOG.info("ignored %s:%s (%s)", repo_name, tag, why)
            self._reply(200, {"status": "ignored", "reason": why})
            return

        key = f"{repo_name}:{tag}:{pushed_at}"
        if already_seen(key):
            LOG.info("deduped %s", key)
            self._reply(200, {"status": "duplicate"})
            return

        status, detail = dispatch(repo_name, tag, pushed_at, pusher)
        if 200 <= status < 300:
            LOG.info("dispatched %s:%s -> %s (%s)", repo_name, tag, GITHUB_REPOSITORY, status)
            self._reply(202, {"status": "dispatched", "repo": repo_name, "tag": tag})
        else:
            # Report the failure so it appears in Docker Hub's delivery history and
            # can be retried, rather than silently dropping a real new tag.
            LOG.error("dispatch failed %s:%s status=%s detail=%s", repo_name, tag, status, detail)
            self._reply(502, {"status": "dispatch failed", "github_status": status})


def main():
    logging.basicConfig(
        level=logging.INFO, stream=sys.stdout,
        format='{"severity":"%(levelname)s","message":%(message)r}',
    )
    missing = [n for n in ("WEBHOOK_SECRET", "GITHUB_REPOSITORY") if not os.environ.get(n)]
    if not DRY_RUN and not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN")
    if missing:
        LOG.error("refusing to start; missing: %s", ", ".join(missing))
        sys.exit(1)
    if not TAG_ALLOW:
        LOG.warning("TAG_ALLOW is empty -- every tag will be ignored (fail-closed)")

    port = int(os.environ.get("PORT", "8080"))
    LOG.info(
        "listening on %d; repos=%s allow=%s deny=%s dry_run=%s",
        port, sorted(ALLOWED_REPOS) or "ANY",
        [p.pattern for p in TAG_ALLOW], [p.pattern for p in TAG_DENY], DRY_RUN,
    )
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
