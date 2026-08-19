#!/usr/bin/env bash
#
# Unit tests for policy/*.rego -- the Rego policies Docker Scout evaluates as
# GATE 2b (see .github/actions/scan/action.yaml).
#
# WHY THESE TESTS EXIST. The scan gate's Rego runs inside `docker scout policy`,
# which needs network access to api.dso.docker.com and a real image -- so the
# only way to exercise a policy there is a full pipeline run against a live
# registry. That is far too slow a loop for logic whose whole job is to say no,
# and it means a broken policy would be discovered by a promotion that should
# have been blocked. Scout embeds OPA, so the identical policy text can be
# evaluated offline against synthetic inputs. That is what this does.
#
# THE CASE THAT MATTERS MOST is `non-dhi`: a policy that fails to reject a
# non-hardened image is worse than no policy, because the run goes green and the
# gate appears to have approved something. `empty` covers the same concern from
# the other side -- a malformed or truncated input document must fail closed
# rather than vacuously pass.
#
#   ./tests/test-policy.sh
#
# Uses `opa` from PATH (CI installs it via .github/actions/install-tools), or a
# locally-present DHI OPA image. Skips cleanly when neither is available, the
# same way tests/lint-actions.sh skips without shellcheck -- these tests must
# never require the network.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
POLICY_DIR="$ROOT/policy"

# Kept in step with the pin in .github/actions/install-tools.
OPA_IMAGE="${OPA_IMAGE:-dhi.io/open-policy-agent:1.19.1}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Prefer a real binary; fall back to the DHI image ONLY if it is already pulled,
# so this stays an offline test.
OPA_CMD=()
if command -v opa >/dev/null 2>&1; then
  OPA_CMD=(opa)
elif command -v docker >/dev/null 2>&1 && docker image inspect "$OPA_IMAGE" >/dev/null 2>&1; then
  OPA_CMD=(docker run --rm --user "$(id -u):$(id -g)"
           -v "$ROOT:$ROOT" -v "$WORK:$WORK" -w "$ROOT" "$OPA_IMAGE")
fi
if (( ${#OPA_CMD[@]} == 0 )); then
  echo "opa not on PATH and $OPA_IMAGE not pulled locally -- skipping policy tests"
  echo "  install: .github/actions/install-tools (CI) or 'docker pull $OPA_IMAGE'"
  exit 0
fi

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

# ---------------------------------------------------------------------------
# Fixtures. Marker values are the real ones observed on the org's mirrored DHI
# images (see attestation-types.json for how that inventory was taken).
#
# Note com.docker.dhi.name is "dhi/node" WITH A SLASH. The mirror repository is
# named <org>/dhi-node with a hyphen, and confusing the two is the single
# easiest way to write a policy that rejects every genuine DHI.
# ---------------------------------------------------------------------------
fixture() { cat >"$WORK/$1.json"; }

fixture dhi-labels <<'EOF'
{"source":{"type":"image","image":{"name":"nicksdemoorg/dhi-node:26-debian13",
 "config":{"config":{"User":"65532","Labels":{
   "com.docker.dhi.name":"dhi/node","com.docker.dhi.distro":"debian-13",
   "com.docker.dhi.definition":"image/node/debian-13/26",
   "com.docker.dhi.entitlement":"public"}}},
 "manifest":{"annotations":{}}}}}
EOF

# Annotations alone must satisfy the gate: labels and annotations are
# independent carriers, and a copy that preserved only one is still a DHI.
fixture dhi-annotations <<'EOF'
{"source":{"type":"image","image":{"name":"nicksdemoorg/dhi-node:24-alpine",
 "config":{"config":{}},
 "manifest":{"annotations":{
   "com.docker.dhi.name":"dhi/node","com.docker.dhi.distro":"alpine-3.23"}}}}}
EOF

# Labels present but explicitly null -- the shape a stock library image has.
fixture non-dhi <<'EOF'
{"source":{"type":"image","image":{"name":"docker.io/library/alpine:3.20",
 "config":{"config":{"Labels":null}},"manifest":{"annotations":{}}}}}
EOF

fixture wrong-prefix <<'EOF'
{"source":{"type":"image","image":{"name":"evil.example/notdhi:1",
 "config":{"config":{"Labels":{
   "com.docker.dhi.name":"totally/node","com.docker.dhi.distro":"debian-13"}}},
 "manifest":{"annotations":{}}}}}
EOF

# A half-populated marker set suggests hand-applied labels rather than a DHI.
fixture no-distro <<'EOF'
{"source":{"type":"image","image":{"name":"suspect/img:1",
 "config":{"config":{"Labels":{"com.docker.dhi.name":"dhi/node"}}},
 "manifest":{"annotations":{}}}}}
EOF

# The documented input paths could not be confirmed against a live
# `docker scout policy` run (it needs api.dso.docker.com), so the policy also
# looks for the marker anywhere in the input. This fixture nests it somewhere the
# documented paths do NOT cover: it must still pass, or a wrong assumption about
# the input schema would reject every genuine DHI.
fixture odd-nesting <<'EOF'
{"source":{"type":"image","image":{"name":"nicksdemoorg/dhi-node:26-debian13",
 "somewhere":{"unexpected":{"Labels":{
   "com.docker.dhi.name":"dhi/node","com.docker.dhi.distro":"debian-13"}}}}}}
EOF

# ...and the fallback must not become a loophole: a wrong prefix found by the
# deep walk is still a refusal.
fixture odd-nesting-wrong <<'EOF'
{"source":{"image":{"deep":{"x":{
   "com.docker.dhi.name":"totally/node","com.docker.dhi.distro":"debian-13"}}}}}
EOF

printf '{}\n' >"$WORK/empty.json"

printf '{"config":{"required_name_prefix":"totally/"}}\n' >"$WORK/cfg-prefix.json"
printf '{"config":{"require_distro":false}}\n' >"$WORK/cfg-nodistro.json"

# ---------------------------------------------------------------------------
eval_field() { # eval_field <fixture> <data-file|-> <rego-path> -> value
  local -a args=(eval -f json -d "$POLICY_DIR")
  [[ "$2" != "-" ]] && args+=(-d "$WORK/$2")
  "${OPA_CMD[@]}" "${args[@]}" -i "$WORK/$1.json" "$3" 2>/dev/null \
    | jq -r '.result[0].expressions[0].value' 2>/dev/null
}

verdict()   { eval_field "$1" "${2:--}" 'data.docker.scout.pass'; }
violations(){ "${OPA_CMD[@]}" eval -f json -d "$POLICY_DIR" -i "$WORK/$1.json" \
                'data.docker.scout.violation' 2>/dev/null \
              | jq -r '.result[0].expressions[0].value | length' 2>/dev/null; }

# ---------------------------------------------------------------------------
echo "== the policy compiles under strict mode"
if "${OPA_CMD[@]}" check --strict "$POLICY_DIR" >"$WORK/check.log" 2>&1; then
  check "opa check --strict" "clean" "clean"
else
  check "opa check --strict" "clean" "$(tr '\n' ' ' <"$WORK/check.log")"
fi

# ---------------------------------------------------------------------------
echo "== dhi-provenance: a genuine DHI passes"
check "marker in config labels"              "true"  "$(verdict dhi-labels)"
check "marker in manifest annotations only"  "true"  "$(verdict dhi-annotations)"
check "passing image reports no violations"  "0"     "$(violations dhi-labels)"
# Guards the one assumption that could reject every legitimate image.
check "marker at an undocumented path"       "true"  "$(verdict odd-nesting)"

echo "== dhi-provenance: everything else is refused"
check "non-DHI control is rejected"          "false" "$(verdict non-dhi)"
check "wrong name prefix is rejected"        "false" "$(verdict wrong-prefix)"
check "name without distro is rejected"      "false" "$(verdict no-distro)"
check "empty input fails CLOSED"             "false" "$(verdict empty)"
check "deep fallback is not a loophole"      "false" "$(verdict odd-nesting-wrong)"

# One violation per failure, not two. A non-DHI image tripping both the
# missing-name and missing-distro rules would report the same problem twice and
# bury the actionable one.
echo "== each failure reports exactly one violation"
check "non-DHI: 1 violation"                 "1"     "$(violations non-dhi)"
check "wrong-prefix: 1 violation"            "1"     "$(violations wrong-prefix)"
check "no-distro: 1 violation"               "1"     "$(violations no-distro)"

# ---------------------------------------------------------------------------
# The gate is configured through --policy-config, so the config plumbing is
# part of the contract: a policy that silently ignores its config would apply
# the default threshold while the workflow claims a stricter one.
echo "== --policy-config overrides take effect"
check "required_name_prefix accepts its value" "true"  "$(verdict wrong-prefix cfg-prefix.json)"
check "required_name_prefix excludes others"   "false" "$(verdict dhi-labels   cfg-prefix.json)"
check "require_distro=false relaxes distro"    "true"  "$(verdict no-distro    cfg-nodistro.json)"
check "require_distro=false still needs a name" "false" "$(verdict non-dhi     cfg-nodistro.json)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
