#!/usr/bin/env python3
"""Pipe jsluice JSONL into redacted request records without raw source retention."""
import argparse
import json
import sys
from pathlib import Path
from recon81.importers import js_record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mapping', type=Path, required=True)
    parser.add_argument('--filename', required=True)
    args = parser.parse_args()
    mapping = {}
    if args.mapping.exists():
        for line in args.mapping.read_text(encoding='utf-8').splitlines():
            if '\t' in line:
                name, url = line.split('\t', 1)
                mapping[name] = url
    base = mapping.get(args.filename)
    failures = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            record = js_record(item, base)
            print(json.dumps(record, ensure_ascii=False))
        except (ValueError, KeyError, TypeError):
            failures += 1
    if failures:
        print('Unresolved or invalid JS records omitted: ' + str(failures), file=sys.stderr)


if __name__ == '__main__':
    main()
