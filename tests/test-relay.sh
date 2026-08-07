#!/usr/bin/env bash
#
# Tests for the Docker Hub webhook relay.
#
# Runs the real relay on a loopback port in DRY_RUN mode and posts real Docker Hub
# payload shapes at it. No GitHub calls, no credentials, no network.
#
# What matters here is what the relay REFUSES. Docker Hub sends no signature, so
# the URL is the only credential, and the blast radius of a leaked URL is decided
# entirely by the checks below. The tag filter is equally load-bearing for a
# different reason: DHI mirrors all ~450 tags of dhi-node, and one upstream rebuild
# without filtering is hundreds of concurrent pipeline runs.
#
#   ./tests/test-relay.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURE="$TESTS_DIR/fixtures/dockerhub-webhook.json"

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

pass=0; fail=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

SECRET="test-secret-$$"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
LOG="$(mktemp)"

WEBHOOK_SECRET="$SECRET" \
GITHUB_REPOSITORY="nickorefice/dhi-gar-pipeline" \
ALLOWED_REPOS="nicksdemoorg/dhi-node" \
TAG_ALLOW='^2[0-9]-debian13$,^24-alpine$' \
TAG_DENY='-dev$' \
DRY_RUN=1 PORT="$PORT" \
  python3 "$ROOT/relay/main.py" >"$LOG" 2>&1 &
RELAY_PID=$!
trap 'kill "$RELAY_PID" 2>/dev/null; rm -f "$LOG"' EXIT

# Wait for the listener rather than sleeping a guessed interval.
wait_for_port() {
  python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); sys.exit(0)
    except OSError:
        time.sleep(0.05)
sys.exit(1)
PY
}

if ! wait_for_port "$PORT"; then
  echo "relay failed to start:"; cat "$LOG"; exit 1
fi

post() { # post <path> <json>
  curl -sS -o /dev/null -w '%{http_code}' -m 10 -X POST \
    -H 'Content-Type: application/json' --data "$2" "http://127.0.0.1:$PORT$1" 2>/dev/null
}
post_body() {
  curl -sS -m 10 -X POST -H 'Content-Type: application/json' --data "$2" "http://127.0.0.1:$PORT$1" 2>/dev/null
}
retag() { jq -c --arg t "$1" '.push_data.tag = $t' "$FIXTURE"; }

echo "== authentication: the URL is the only credential Docker Hub can present"
check "correct secret accepted"        "202" "$(post "/hook/$SECRET" "$(retag 26-debian13)")"
check "wrong secret -> 404"            "404" "$(post "/hook/wrong-secret" "$(retag 26-debian13)")"
check "no secret -> 404"               "404" "$(post "/hook" "$(retag 26-debian13)")"
check "secret as query param -> 404"   "404" "$(post "/hook?secret=$SECRET" "$(retag 26-debian13)")"
check "trailing slash tolerated"       "202" "$(post "/hook/$SECRET/" "$(retag 24-alpine)")"

echo "== payload validation"
check "non-Hub JSON rejected"          "400" "$(post "/hook/$SECRET" '{"hello":"world"}')"
check "malformed JSON rejected"        "400" "$(post "/hook/$SECRET" '{not json')"
check "missing tag rejected"           "400" "$(post "/hook/$SECRET" '{"repository":{"repo_name":"nicksdemoorg/dhi-node"},"push_data":{}}')"
check "empty body rejected"            "413" "$(post "/hook/$SECRET" '')"

echo "== a leaked URL still cannot pick an arbitrary image"
check "other repository -> 403" "403" \
  "$(post "/hook/$SECRET" "$(jq -c '.repository.repo_name = "attacker/evil"' "$FIXTURE")")"

echo "== tag filter: without it, one upstream rebuild floods CI"
check "allow-listed tag dispatches"    "202" "$(post "/hook/$SECRET" "$(retag 24-debian13)")"
check "unlisted tag ignored (200, not an error)" "200" "$(post "/hook/$SECRET" "$(retag 22-alpine3.22)")"
check "TAG_DENY beats TAG_ALLOW"       "200" "$(post "/hook/$SECRET" "$(retag 26-debian13-dev)")"
check "ignored responses say why" "no TAG_ALLOW pattern matched" \
  "$(post_body "/hook/$SECRET" "$(retag 22-alpine3.22)" | jq -r .reason)"

echo "== duplicate delivery"
DUP="$(retag 26-debian13)"
post "/hook/$SECRET" "$DUP" >/dev/null
check "same repo+tag+pushed_at deduped" "duplicate" \
  "$(post_body "/hook/$SECRET" "$DUP" | jq -r .status)"
check "different pushed_at is not a duplicate" "dispatched" \
  "$(post_body "/hook/$SECRET" "$(jq -c '.push_data.pushed_at = 1786060999' <<<"$DUP")" | jq -r .status)"

echo "== health endpoint reveals no configuration"
check "GET /healthz -> 200" "200" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -m 10 "http://127.0.0.1:$PORT/healthz" 2>/dev/null)"
check "healthz body has no repo/tag config" "false" \
  "$(curl -sS -m 10 "http://127.0.0.1:$PORT/healthz" 2>/dev/null | jq -r 'tostring | test("dhi-node|debian13")')"
check "GET on the hook path -> 404" "404" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -m 10 "http://127.0.0.1:$PORT/hook/$SECRET" 2>/dev/null)"

echo "== fail-closed when misconfigured"
check "empty TAG_ALLOW ignores everything" "200" "$(
  P2="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  WEBHOOK_SECRET=s2 GITHUB_REPOSITORY=o/r ALLOWED_REPOS=nicksdemoorg/dhi-node \
  TAG_ALLOW='' DRY_RUN=1 PORT="$P2" python3 "$ROOT/relay/main.py" >/dev/null 2>&1 &
  P2PID=$!
  wait_for_port "$P2"
  curl -sS -o /dev/null -w '%{http_code}' -m 10 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -c '.push_data.tag = "26-debian13"' "$FIXTURE")" "http://127.0.0.1:$P2/hook/s2" 2>/dev/null
  kill "$P2PID" 2>/dev/null
)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
