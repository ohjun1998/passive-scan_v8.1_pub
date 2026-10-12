#!/usr/bin/env bash
set -euo pipefail
GROUP=${1:-00}
[[ "$GROUP" =~ ^[0-9]{2}$ ]] || exit 2
[[ -f targets.txt && -f scope.txt ]] || { echo 'targets.txt and scope.txt are required'; exit 2; }
mkdir -p results
# Tagged hosts are validated and grouped before invoking external tools.
python3 - <<'PY'
from pathlib import Path
from recon81.core import Scope, private_write
scope=Scope(Path('scope.txt').read_text().splitlines())
groups={}
for line in Path('targets.txt').read_text().splitlines():
    tag, host=line.strip().split(':',1)
    expected='*.'+tag[5:] if tag.startswith('wild_') else tag
    if expected not in scope.patterns or not scope.allows('https://'+host):
        raise ValueError('Invalid tagged target')
    groups.setdefault(tag,set()).add(host)
for tag,hosts in groups.items():
    private_write(Path('results')/(tag+'_all_targets.txt'),'\n'.join(sorted(hosts))+'\n')
PY
for targets in results/*_all_targets.txt; do
  [[ -f "$targets" ]] || continue
  base=$(basename "$targets")
  domain=${base%_all_targets.txt}
  waybackurls < "$targets" | uro > "results/${domain}_waybackurls_${GROUP}.txt"
  gau --threads 1 < "$targets" | uro > "results/${domain}_gau_${GROUP}.txt"
  : > "results/${domain}_crawl_${GROUP}.txt"
  if [[ "${ENABLE_CRAWL:-false}" == true ]]; then
    python3 guarded_crawl.py --active --seeds "$targets" --scope-file scope.txt \
      --output "results/${domain}_crawl_${GROUP}.txt" --state results/active_guard.sqlite3
  fi
  if [[ "${ENABLE_JS_DOWNLOAD:-false}" == true ]]; then
    cat "results/${domain}_"*"_${GROUP}.txt" | python3 -c '
import sys
from urllib.parse import urlsplit
for u in sorted(set(x.strip() for x in sys.stdin if x.strip())):
    if urlsplit(u).path.lower().endswith(".js"): print(u)
' > "results/${domain}_js_targets.txt"
    js_scope="$domain"
    [[ "$js_scope" != wild_* ]] || js_scope="*.${js_scope#wild_}"
    python3 download_js.py --active --urls "results/${domain}_js_targets.txt" \
      --output "results/${domain}_js_files_${GROUP}" --mapping "results/${domain}_js_mapping.txt" \
      --scope "$js_scope" --state results/active_guard.sqlite3 --cache "results/js_download_cache_${GROUP}.jsonl"
  fi
done
