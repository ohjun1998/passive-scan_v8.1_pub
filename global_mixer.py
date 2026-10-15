#!/usr/bin/env python3
"""Preserve discoveries in Inventory and create a separate deterministic probe queue."""
import json
from pathlib import Path
from recon81.network_policy import NetworkPolicy
from recon81.core import Inventory, Scope, private_write
from recon81.pipeline import (execution_plan, ingest_saved, make_absolute,
                              get_safe_domain, normalize_dynamic_path)


def run_mixer():
    if not Path('targets.txt').exists(): return
    scope=Scope(Path('targets.txt').read_text(encoding='utf-8').splitlines())
    with Inventory('reports/request_inventory.sqlite3') as inventory:
        stats=ingest_saved('results',scope,inventory,history_files=['previous_report/master_url_db.txt'])
        records=[r for r in inventory.records() if scope.allows(r['url'])]
    selected,deferred,summary=execution_plan(records,NetworkPolicy(scope))
    summary['ingestion']=stats
    # All 20 workers retain their existing independent -rl 10 -t 5 settings.
    for i in range(20):
        private_write(Path('chunks')/f'chunk_{i:02d}.txt',''.join(u+'\n' for u in selected[i::20]))
    private_write('reports/execution_deferred.jsonl',''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in deferred))
    private_write('reports/execution_plan.json',json.dumps(summary,ensure_ascii=False,indent=2))
    private_write('reports/master_url_db.txt',''.join(url+'\n' for url in sorted({r['url'] for r in records})))
    print(f"[+] 전체 URL {summary['total_urls']}개 보존 / 실행 {len(selected)}개 / 보류 {len(deferred)}개 / 파싱 오류 {stats['parse_errors']}개")


if __name__=='__main__': run_mixer()
