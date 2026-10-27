#!/usr/bin/env bash
# Usage: audit-ids.sh <checkout-dir>
#
# Prints, one per line, the advisory ids that fail the audit policy for the
# tree checked out at <checkout-dir>:
#   - every RustSec vulnerability cargo-audit reports (the tree's own
#     .cargo/audit.toml ignores apply)
#   - high/critical dashboard advisories from `bun audit`, minus the ids
#     listed in the tree's dashboard/.bun-audit-ignore
#
# Exits 2 when either tool's output isn't the JSON it should be, so a
# broken audit never reads as "no advisories".
set -euo pipefail

dir=$1

cargo_json=$(cd "$dir" && cargo audit --json) || true # non-zero on findings
if ! jq -e '.vulnerabilities.list | type == "array"' >/dev/null 2>&1 <<<"$cargo_json"; then
  echo "cargo audit produced no usable JSON for $dir" >&2
  exit 2
fi
jq -r '.vulnerabilities.list[].advisory.id' <<<"$cargo_json"

# Reads dashboard/bun.lock only; no install needed.
bun_json=$(cd "$dir/dashboard" && bun audit --json 2>/dev/null) || true
if ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$bun_json"; then
  echo "bun audit produced no usable JSON for $dir/dashboard" >&2
  exit 2
fi
ignore_file="$dir/dashboard/.bun-audit-ignore"
if [ -f "$ignore_file" ]; then
  ignore=$({ grep -oE '^GHSA-[a-z0-9-]+' "$ignore_file" || true; } |
    jq -Rsc 'split("\n") | map(select(length > 0))')
else
  ignore='[]'
fi
jq -r --argjson ignore "$ignore" '
  [.[][] | select(.severity == "high" or .severity == "critical")
         | .url | split("/") | last]
  | unique[] | select(IN($ignore[]) | not)' <<<"$bun_json"
