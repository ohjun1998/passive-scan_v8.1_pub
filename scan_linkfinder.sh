#!/usr/bin/env bash
set -euo pipefail
GROUP_SUFFIX=${1:-00}
mkdir -p results
version=${JS_ANALYZER_VERSION:-}
if [[ -z "$version" ]]; then version=$(python3 js_asset_cache.py version --binary "$(command -v jsluice)"); fi
for dir in results/*_js_files_"${GROUP_SUFFIX}"; do
  [ -d "$dir" ] || continue
  base=$(basename "$dir")
  safe_domain=${base%_js_files_*}
  mapping="results/${safe_domain}_js_mapping.txt"
  output="results/${safe_domain}_js_requests_${GROUP_SUFFIX}.jsonl"
  : > "$output"
  chmod 600 "$output"
  cache="results/js_download_cache_${GROUP_SUFFIX}.jsonl"
  python3 js_asset_cache.py reuse --cache "$cache" --mapping "$mapping" --analyzer-version "$version" >> "$output"
  for js_file in "$dir"/*.js; do
    [ -f "$js_file" ] || continue
    if [ -f "$cache" ]; then
      if [[ $(python3 js_asset_cache.py needs-analysis --cache "$cache" --source-file "$js_file" --analyzer-version "$version") == false ]]; then continue; fi
      extracted="$dir/.extracted.jsonl"
      : > "$extracted"; chmod 600 "$extracted"
      jsluice urls "$js_file" | python3 sanitize_js_requests.py --mapping "$mapping" --filename "$(basename "$js_file")" > "$extracted"
      python3 js_asset_cache.py update --cache "$cache" --source-file "$js_file" --records "$extracted" --analyzer-version "$version" >> "$output"
      rm -f "$extracted"
    else
      jsluice urls "$js_file" | python3 sanitize_js_requests.py --mapping "$mapping" --filename "$(basename "$js_file")" >> "$output"
    fi
  done
  # Keep legacy URL reports working; new metadata remains in the JSONL file.
  jq -r 'select(.method == "GET" or .method == "UNKNOWN") | .url' "$output" | sort -u > "results/${safe_domain}_linkfinder_${GROUP_SUFFIX}.txt"
done
