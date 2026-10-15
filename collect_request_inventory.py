#!/usr/bin/env python3
"""Build every report from the canonical saved-evidence inventory, without requests."""
import argparse
import json
from pathlib import Path
from recon81.core import Inventory, Scope, private_write
from recon81.pipeline import ingest_saved
from recon81.reports import generate


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope-file',type=Path,default=Path('targets.txt'))
    parser.add_argument('--results',type=Path,default=Path('results'))
    parser.add_argument('--db',type=Path,default=Path('reports/request_inventory.sqlite3'))
    parser.add_argument('--output',type=Path,default=Path('reports/requests'))
    parser.add_argument('--xlsx',action='store_true')
    args=parser.parse_args()
    scope=Scope(args.scope_file.read_text(encoding='utf-8').splitlines())
    with Inventory(args.db) as inventory:
        stats=ingest_saved(args.results,scope,inventory,history_files=['previous_report/master_url_db.txt'])
        records=[r for r in inventory.records() if scope.allows(r['url'])]
        ids={r['observation_id'] for r in records}
        events=[event for event in inventory.capture_events() if event['observation_id'] in ids]
        generate(records,args.output,args.xlsx,capture_events=events)
    private_write(args.output.parent/'ingestion_summary.json',json.dumps(stats,ensure_ascii=False,indent=2))
    print('inventory: '+json.dumps(stats,ensure_ascii=False)+', network_requests_sent=0')


if __name__=='__main__': main()
