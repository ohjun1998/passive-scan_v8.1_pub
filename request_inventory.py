#!/usr/bin/env python3
"""Import and report local HTTP evidence. This command never sends HTTP requests."""
import argparse
import json
import sys
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from recon81 import __version__
from recon81.core import Inventory, Scope, normalize_resource_headers
from recon81.importers import load_records
from recon81.context import attach_context, clean_context, STATES


def label_args(parser):
    for key in ('actor','tenant','scenario','capture_id'):
        parser.add_argument('--'+key.replace('_','-'),default=None)
    parser.add_argument('--expected-access',choices=['allow','deny','unknown'],default=None)
    parser.add_argument('--operation',choices=['read','write','unknown'],default=None)


def labels(args):
    return clean_context({k:getattr(args,k,None) or '' for k in ('actor','tenant','scenario','capture_id','expected_access','operation')})


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
    imp.add_argument('--format', choices=['auto', 'har', 'burp', 'jsluice', 'jsonl', 'urls','openapi','html'], default='auto')
    imp.add_argument('--base-url', help='Original JS URL used to resolve relative endpoints')
    imp.add_argument('--include-text', action='store_true', help='Retain free text using best-effort redaction; review before sharing')
    imp.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    imp.add_argument('--resource-header', action='append', default=[], help='Non-secret header that selects a resource; repeatable')
    scope_args(imp)
    label_args(imp)
    rep = commands.add_parser('report', help='Local HTML / JSONL / Postman review collection / optional XLSX')
    rep.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    rep.add_argument('--output', type=Path, default=Path('reports/requests'))
    rep.add_argument('--xlsx', action='store_true')
    rep.add_argument('--ignore-response-field',action='append',default=[],help='Exact JSON path ignored for comparison only; evidence remains intact')
    rep.add_argument('--resource-header', action='append', default=[], help='Include this non-secret resource selector in comparison identity; repeatable')
    scope_args(rep)
    review=commands.add_parser('review',help='Save a human review conclusion or import dashboard review edits')
    review.add_argument('--db',type=Path,default=Path('reports/request_inventory.sqlite3'))
    review.add_argument('--id',help='Observation ID')
    review.add_argument('--state',choices=STATES)
    review.add_argument('--note',default='')
    review.add_argument('--file',type=Path,help='Dashboard review edits JSON')
    args = parser.parse_args(argv)
    try:
        if args.command == 'import':
            scope = parse_scope(args)
            resource_headers = normalize_resource_headers(args.resource_header)
            total = skipped = 0
            # One transaction for all inputs: invalid input cannot leave a partial import.
            with Inventory(args.db) as inventory:
                for path in args.inputs:
                    for record in load_records(path, args.format, args.base_url, args.include_text):
                        if scope.allows(record['url']):
                            if resource_headers:
                                record['resource_headers'] = normalize_resource_headers([*record.get('resource_headers', []), *resource_headers])
                            context=dict(record.get('context') or {})
                            context.update(labels(args))
                            inventory.add(attach_context(record,context))
                            total += 1
                        else:
                            skipped += 1
            print(json.dumps({'imported_records': total, 'out_of_scope_records': skipped, 'network_requests_sent': 0}))
        elif args.command == 'review':
            if not args.db.is_file(): raise ValueError('Inventory DB does not exist')
            if args.file:
                if args.id or args.state: raise ValueError('Use either --file or --id/--state')
                from recon81.core import read_limited
                items=json.loads(read_limited(args.file)).get('reviews')
                if not isinstance(items,list) or len(items)>10000: raise ValueError('Invalid review edits')
            else:
                if not args.id or not args.state: raise ValueError('--id and --state are required')
                items=[{'observation_id':args.id,'state':args.state,'note':args.note}]
            with Inventory(args.db) as inventory:
                for item in items: inventory.review(item['observation_id'],item['state'],item.get('note',''))
            print(json.dumps({'updated_reviews':len(items),'network_requests_sent':0}))
        else:
            if not args.db.is_file():
                raise ValueError('Inventory DB does not exist; import data first')
            from recon81.reports import generate
            with Inventory(args.db) as inventory:
                scope = parse_scope(args) if args.scope or args.scope_file else None
                records = [r for r in inventory.records() if scope is None or scope.allows(r['url'])]
                selected = {r['observation_id'] for r in records}
                events = (event for event in inventory.capture_events() if event['observation_id'] in selected)
                count = generate(records, args.output, args.xlsx, ignore_fields=args.ignore_response_field,
                                 capture_events=events, resource_headers=normalize_resource_headers(args.resource_header))
            print(json.dumps({'reported_records': count, 'output': str(args.output), 'network_requests_sent': 0}))
        return 0
    except (ValueError, KeyError, OSError, TypeError, RecursionError, ET.ParseError, sqlite3.Error) as error:
        # Do not echo exception text: malformed input may contain credentials.
        print('Import/report failed (' + type(error).__name__ + '). Check input format, scope and local file permissions.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
