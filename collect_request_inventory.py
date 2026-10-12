#!/usr/bin/env python3
"""Build the v8.1 inventory from existing recon results; never makes network calls."""
import argparse
import glob
from pathlib import Path
from recon81.core import Inventory, Scope
from recon81.importers import load_records
from recon81.reports import generate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope-file', type=Path, default=Path('targets.txt'))
    parser.add_argument('--results', type=Path, default=Path('results'))
    parser.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    parser.add_argument('--output', type=Path, default=Path('reports/requests'))
    parser.add_argument('--xlsx', action='store_true')
    args = parser.parse_args()
    scope = Scope(args.scope_file.read_text(encoding='utf-8').splitlines())
    count = skipped = 0
    with Inventory(args.db) as inventory:
        paths = sorted(args.results.glob('*_js_requests_*.jsonl'))
        for path in paths:
            for r in load_records(path):
                if scope.allows(r['url']):
                    inventory.add(r)
                    count += 1
                else:
                    skipped += 1
        # Archive URLs have unknown methods: do not label them as observed GETs.
        for pattern in ('*_gau*.txt', '*_waybackurls*.txt', '*_katana*.txt', '*_crawl*.txt'):
            for path in sorted(args.results.glob(pattern)):
                for r in load_records(path, fmt='urls'):
                    if scope.allows(r['url']):
                        inventory.add(r)
                        count += 1
                    else:
                        skipped += 1
        inventory.conn.commit()
        generate([r for r in inventory.records() if scope.allows(r['url'])], args.output, args.xlsx)
    print('v8.1 inventory: imported=' + str(count) + ', out_of_scope=' + str(skipped) + ', network_requests_sent=0')


if __name__ == '__main__':
    main()
