#!/usr/bin/env bash
#
# Unit tests for scripts/lib/expand-config.jq -- the expansion of the
# admin-edited sync-config.yaml into the flat allow list every pipeline
# consumer iterates (the poll, the dispatch re-check, the promote hold check,
# the STATUS.md dashboard).
#
# The inheritance rules are the part most likely to be quietly wrong: jq's
# `//` operator treats false as absent, so a naive chain silently ignores an
# explicit tag-level `requireVex: false` under an image-level `true`. That
# exact case is asserted here. Validation must fail LOUDLY -- a config typo
# that silently shrinks the allow list would read as "nothing to sync, ever".
#
#   ./tests/test-expand-config.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
EXPAND="$ROOT/scripts/lib/expand-config.jq"

# Same converter the pipeline library uses (python3 + PyYAML); same graceful
# skip as tests/lint-actions.sh where it is unavailable.
python3 -c 'import yaml' 2>/dev/null \
  || { echo "python3+PyYAML not available -- skipping expand-config tests"; exit 0; }

pass=0; fail=0
check() { # check <name> <expected> <actual>
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

expand() { # expand <yaml-file> -> expanded JSON on stdout, jq's exit code
  python3 -c 'import json, sys, yaml; json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)' "$1" \
    | jq -f "$EXPAND" 2>/dev/null
}

expand_verdict() { # expand_verdict <yaml-file> -> "ok" or "rejected"
  if expand "$1" >/dev/null; then echo "ok"; else echo "rejected"; fi
}

# ---------------------------------------------------------------------------
echo "== inheritance: image defaults flow to tags, explicit tag values win"
cat >"$WORK/inherit.yaml" <<'EOF'
images:
  - repo: dhi-a
    requireVex: true
    tags:
      - plain-string-tag
      - tag: explicit-false
        requireVex: false
      - tag: with-note
        note: hello
  - repo: dhi-b
    hold: true
    tags:
      - held-by-image
      - tag: unheld
        hold: false
  - repo: dhi-c
    tags: [ bare ]
EOF
out="$(expand "$WORK/inherit.yaml")"
check "entry count"                        "6"     "$(jq -r 'length' <<<"$out")"
check "string tag inherits image requireVex" "true"  "$(jq -r '.[0].requireVex' <<<"$out")"
check "string tag hold defaults false"     "false" "$(jq -r '.[0].hold' <<<"$out")"
check "explicit tag false beats image true (the // trap)" "false" "$(jq -r '.[1].requireVex' <<<"$out")"
check "note passthrough"                   "hello" "$(jq -r '.[2].note' <<<"$out")"
check "absent note is null"                "null"  "$(jq -r '.[0].note' <<<"$out")"
check "image-level hold inherits"          "true"  "$(jq -r '.[3].hold' <<<"$out")"
check "explicit tag hold false beats image true" "false" "$(jq -r '.[4].hold' <<<"$out")"
check "no defaults at all -> false/false"  "false false" "$(jq -r '.[5] | "\(.requireVex) \(.hold)"' <<<"$out")"
check "repo carried onto every tag"        "dhi-b" "$(jq -r '.[3].repo' <<<"$out")"

# ---------------------------------------------------------------------------
echo "== validation: a config typo must stop the poll, not shrink the list"
cat >"$WORK/dup.yaml" <<'EOF'
images:
  - repo: dhi-a
    tags: [ same, same ]
EOF
check "duplicate repo:tag rejected"        "rejected" "$(expand_verdict "$WORK/dup.yaml")"

cat >"$WORK/no-tags.yaml" <<'EOF'
images:
  - repo: dhi-a
EOF
check "image without tags rejected"        "rejected" "$(expand_verdict "$WORK/no-tags.yaml")"

cat >"$WORK/no-repo.yaml" <<'EOF'
images:
  - tags: [ x ]
EOF
check "image without repo rejected"        "rejected" "$(expand_verdict "$WORK/no-repo.yaml")"

cat >"$WORK/no-tag-key.yaml" <<'EOF'
images:
  - repo: dhi-a
    tags:
      - note: mapping without .tag
EOF
check "mapping tag entry without .tag rejected" "rejected" "$(expand_verdict "$WORK/no-tag-key.yaml")"

cat >"$WORK/bad-bool.yaml" <<'EOF'
images:
  - repo: dhi-a
    tags:
      - tag: x
        requireVex: definitely
EOF
check "non-boolean requireVex rejected"    "rejected" "$(expand_verdict "$WORK/bad-bool.yaml")"

cat >"$WORK/empty.yaml" <<'EOF'
images: []
EOF
check "empty images list rejected"         "rejected" "$(expand_verdict "$WORK/empty.yaml")"

printf 'no-images: here\n' >"$WORK/no-images.yaml"
check "missing images key rejected"        "rejected" "$(expand_verdict "$WORK/no-images.yaml")"

# ---------------------------------------------------------------------------
echo "== the repo's real config expands cleanly"
check "sync-config.yaml is valid"          "ok"    "$(expand_verdict "$ROOT/sync-config.yaml")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
