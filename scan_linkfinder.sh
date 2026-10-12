#!/usr/bin/env bash
set -euo pipefail
GROUP_SUFFIX=${1:-00}
mkdir -p results
for dir in results/*_js_files_"${GROUP_SUFFIX}"; do
  [ -d "$dir" ] || continue
  base=$(basename "$dir")
  safe_domain=${base%_js_files_*}
  mapping="results/${safe_domain}_js_mapping.txt"
  output="results/${safe_domain}_js_requests_${GROUP_SUFFIX}.jsonl"
  : > "$output"
  chmod 600 "$output"
  for js_file in "$dir"/*.js; do
    [ -f "$js_file" ] || continue
    jsluice urls "$js_file" | python3 sanitize_js_requests.py --mapping "$mapping" --filename "$(basename "$js_file")" >> "$output"
  done
  # Keep legacy URL reports working; new metadata remains in the JSONL file.
  jq -r 'select(.method == "GET" or .method == "UNKNOWN") | .url' "$output" | sort -u > "results/${safe_domain}_linkfinder_${GROUP_SUFFIX}.txt"
done
