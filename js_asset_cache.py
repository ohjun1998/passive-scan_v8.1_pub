#!/usr/bin/env python3
"""Offline JS cache reuse and content/analyzer change tracking."""
import argparse
import json
from pathlib import Path
from recon81.assets import file_hash,update_analysis,reuse_analysis,entries,reusable
from recon81.importers import load_records


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    version=sub.add_parser('version'); version.add_argument('--binary',type=Path,required=True)
    reuse=sub.add_parser('reuse'); update=sub.add_parser('update'); needs=sub.add_parser('needs-analysis')
    for cmd in (reuse,update,needs):
        cmd.add_argument('--cache',type=Path,required=True); cmd.add_argument('--analyzer-version',required=True)
    reuse.add_argument('--mapping',type=Path,required=True)
    update.add_argument('--source-file',type=Path,required=True); update.add_argument('--records',type=Path,required=True)
    needs.add_argument('--source-file',type=Path,required=True)
    args=p.parse_args()
    if args.command=='version': print('jsluice:'+file_hash(args.binary)+'|adapter:8.2.0'); return
    if args.command=='needs-analysis':
        item=entries(args.cache).get(args.source_file.stem,{})
        print('false' if reusable(item,args.analyzer_version) and item.get('content_hash')==file_hash(args.source_file) else 'true'); return
    if args.command=='reuse': records=reuse_analysis(args.cache,args.mapping,args.analyzer_version)
    else:
        records=list(load_records(args.records))
        records=update_analysis(args.cache,args.source_file.stem,file_hash(args.source_file),args.analyzer_version,records)
    for record in records: print(json.dumps(record,ensure_ascii=False))

if __name__=='__main__': main()
