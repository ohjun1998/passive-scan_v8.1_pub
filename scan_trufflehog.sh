#!/usr/bin/env bash
set -euo pipefail
umask 077
GROUP_SUFFIX=${1:-00}
[[ "$GROUP_SUFFIX" =~ ^[0-9]{2}$ ]] || exit 2
MAX_SCANNERS=${TRUFFLEHOG_WORKERS:-2}
[[ "$MAX_SCANNERS" =~ ^[1-9][0-9]*$ ]] && (( MAX_SCANNERS <= 16 )) || exit 2
mkdir -p results
scratch_dir=$(mktemp -d results/.trufflehog.XXXXXXXX)
trap 'rm -rf -- "$scratch_dir"' EXIT

scan_truffle() {
    local dir=$1 group=$2 basename_dir safe_domain raw output
    basename_dir=$(basename "$dir")
    safe_domain=${basename_dir%_js_files_*}
    raw=$(mktemp "$scratch_dir/raw.XXXXXXXX")
    output="results/${safe_domain}_trufflehog_${group}.txt"
    rm -f -- "$output"
    # Verification stays disabled: extracted secrets never trigger provider calls.
    if ! trufflehog filesystem "$dir" --no-verification --json > "$raw" 2>/dev/null; then
        printf '%s\n' 'TruffleHog failed; findings are incomplete.' >&2
        rm -f -- "$raw"
        return 1
    fi
    if ! jq -r '((.SourceMetadata.Data.Filesystem.file // "unknown.js") | split("/") | last) + "\t[" + (.DetectorName // "Secret") + "] [REDACTED]"' "$raw" > "$output"; then
        rm -f -- "$raw" "$output"
        return 1
    fi
    rm -f -- "$raw"
}

pids=()
failed=0
for dir in results/*_js_files_"${GROUP_SUFFIX}"; do
    [[ -d "$dir" ]] || continue
    scan_truffle "$dir" "$GROUP_SUFFIX" &
    pids+=("$!")
    if (( ${#pids[@]} >= MAX_SCANNERS )); then
        for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
        pids=()
    fi
done
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
exit "$failed"
