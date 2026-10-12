#!/usr/bin/env python3
"""Import and report local HTTP evidence. This command never sends HTTP requests."""
import argparse
import json
import sys
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from recon81 import __version__
from recon81.core import Inventory, Scope
from recon81.importers import load_records


def scope_args(parser):
    parser.add_argument('--scope', action='append', default=[], help='Exact host or *.example.com; repeatable')
    parser.add_argument('--scope-file', type=Path, help='One host pattern per line')


def parse_scope(args):
    patterns = args.scope[:]
    if args.scope_file:
        patterns.extend(args.scope_file.read_text(encoding='utf-8').splitlines())
    return Scope(patterns)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    imp = commands.add_parser('import', help='Offline import: Burp XML, HAR, jsluice / recorder JSONL, URL lists')
    imp.add_argument('inputs', nargs='+', type=Path)
    imp.add_argument('--format', choices=['auto', 'har', 'burp', 'jsluice', 'jsonl', 'urls'], default='auto')
    imp.add_argument('--base-url', help='Original JS URL used to resolve relative endpoints')
    imp.add_argument('--include-text', action='store_true', help='Retain free text using best-effort redaction; review before sharing')
    imp.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    scope_args(imp)
    rep = commands.add_parser('report', help='Local HTML / JSONL / Postman review collection / optional XLSX')
    rep.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    rep.add_argument('--output', type=Path, default=Path('reports/requests'))
    rep.add_argument('--xlsx', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'import':
            scope = parse_scope(args)
            total = skipped = 0
            # One transaction for all inputs: invalid input cannot leave a partial import.
            with Inventory(args.db) as inventory:
                for path in args.inputs:
                    for record in load_records(path, args.format, args.base_url, args.include_text):
                        if scope.allows(record['url']):
                            inventory.add(record)
                            total += 1
                        else:
                            skipped += 1
            print(json.dumps({'imported_records': total, 'out_of_scope_records': skipped, 'network_requests_sent': 0}))
        else:
            if not args.db.is_file():
                raise ValueError('Inventory DB does not exist; import data first')
            from recon81.reports import generate
            with Inventory(args.db) as inventory:
                count = generate(list(inventory.records()), args.output, args.xlsx)
            print(json.dumps({'reported_records': count, 'output': str(args.output), 'network_requests_sent': 0}))
        return 0
    except (ValueError, KeyError, OSError, TypeError, RecursionError, ET.ParseError, sqlite3.Error) as error:
        # Do not echo exception text: malformed input may contain credentials.
        print('Import/report failed (' + type(error).__name__ + '). Check input format, scope and local file permissions.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
