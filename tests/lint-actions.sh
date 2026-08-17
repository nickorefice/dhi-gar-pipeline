#!/usr/bin/env bash
#
# lint-actions.sh -- shellcheck every bash run block embedded in the composite
# action YAMLs, plus the pipeline library itself.
#
# actionlint covers run blocks in WORKFLOW files; nothing standard covers
# composite actions, and this repo keeps its entire pipeline in them -- so
# without this, moving the code from scripts/ into YAML would have silently
# dropped all shell linting. Run blocks that source the pipeline library are
# checked CONCATENATED after it, so functions and globals resolve and a
# typo'd helper name is a lint error rather than a runtime CI failure.
#
#   ./tests/lint-actions.sh

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"

command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed -- skipping action lint"; exit 0; }
python3 -c 'import yaml' 2>/dev/null || { echo "python3+PyYAML not available -- skipping action lint"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. The library itself, extracted from pipeline-env.
"$TESTS_DIR/extract-pipeline-lib.sh" >"$WORK/pipeline-lib.sh"

# 2. Every run block from every composite action, one file each.
python3 - "$ROOT" "$WORK" <<'PY'
import glob, os, sys, yaml

root, work = sys.argv[1], sys.argv[2]
for path in sorted(glob.glob(os.path.join(root, ".github/actions/*/action.yaml"))):
    name = os.path.basename(os.path.dirname(path))
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    for i, step in enumerate(doc.get("runs", {}).get("steps", [])):
        run = step.get("run")
        if not run:
            continue
        out = os.path.join(work, f"runblock--{name}--{i}.sh")
        with open(out, "w") as fh:
            fh.write("# shellcheck shell=bash\n")
            fh.write(run)
PY

failed=0
checked=0
for f in "$WORK"/runblock--*.sh; do
  [[ -f "$f" ]] || continue
  target="$f"
  # Snippets that source the materialised library are linted with the library
  # prepended, so every helper they call is defined in the checked file.
  if grep -q 'dhi-pipeline-lib\.sh"$' "$f" && [[ "$f" != *runblock--pipeline-env--* ]]; then
    cat "$WORK/pipeline-lib.sh" "$f" >"$f.withlib"
    target="$f.withlib"
  fi
  label="${f##*/runblock--}"
  if shellcheck --shell=bash "$target"; then
    checked=$((checked + 1))
  else
    echo "shellcheck FAILED for action run block: ${label%.sh}" >&2
    failed=$((failed + 1))
  fi
done

echo "shellcheck: pipeline library"
if ! shellcheck --shell=bash "$WORK/pipeline-lib.sh"; then
  failed=$((failed + 1))
fi

if (( failed > 0 )); then
  echo "lint-actions: $failed file(s) failed shellcheck" >&2
  exit 1
fi
echo "lint-actions: pipeline library + $checked action run block(s) clean"
