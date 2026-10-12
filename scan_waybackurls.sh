#!/usr/bin/env bash
set -euo pipefail
[[ -f targets.txt ]] || exit 2
mkdir -p results
while IFS= read -r domain; do
  [[ "$domain" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+$ ]] || continue
  printf '%s\n' "$domain" | waybackurls | sort -u > "results/${domain}_waybackurls.txt"
done < targets.txt
