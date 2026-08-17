#!/usr/bin/env bash
#
# extract-pipeline-lib.sh -- print the pipeline library embedded in
# .github/actions/pipeline-env/action.yaml.
#
# The library's single source of truth is that YAML file; CI materialises it to
# $RUNNER_TEMP and sources it. The offline tests source what THIS script prints,
# so the code under test is byte-for-byte the code the pipeline runs. If the
# extraction ever drifts (indentation change, renamed heredoc marker), the
# first-line sanity check below fails loudly instead of sourcing garbage.
#
#   source <(./tests/extract-pipeline-lib.sh)     # or capture to a file first

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TESTS_DIR/.." && pwd)"
YAML="$ROOT/.github/actions/pipeline-env/action.yaml"

[[ -f "$YAML" ]] || { echo "extract-pipeline-lib: $YAML not found" >&2; exit 1; }

# The heredoc body sits between the <<'DHI_PIPELINE_LIB_EOF' line and the
# closing marker, indented by the YAML block scalar's 8 spaces. YAML strips
# that indent at runtime; we strip the same amount here.
LIB="$(awk '
  /<<'\''DHI_PIPELINE_LIB_EOF'\''/ { grab=1; next }
  grab && $0 ~ /^[[:space:]]*DHI_PIPELINE_LIB_EOF[[:space:]]*$/ { grab=0; exit }
  grab { print }
' "$YAML" | sed -E 's/^ {8}//')"

[[ "$(head -1 <<<"$LIB")" == "# shellcheck shell=bash" ]] \
  || { echo "extract-pipeline-lib: extraction drifted -- unexpected first line: $(head -1 <<<"$LIB")" >&2; exit 1; }

printf '%s\n' "$LIB"
