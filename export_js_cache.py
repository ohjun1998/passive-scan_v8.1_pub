#!/usr/bin/env python3
"""Export fresh previously recorded JS download metadata without contacting targets."""
import argparse
import json
import sqlite3
from pathlib import Path
from recon81.core import private_write
from recon81.network_policy import NetworkPolicy, scope_from_file


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--scope-file',type=Path,required=True)
    args=p.parse_args()
    rows=[]
    policy=NetworkPolicy(scope_from_file(args.scope_file))
    if args.db.exists():
        conn=sqlite3.connect('file:'+str(args.db)+'?mode=ro',uri=True)
        try:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='js_cache'").fetchone():
                has_metadata='metadata' in {x[1] for x in conn.execute('PRAGMA table_info(js_cache)')}
                from recon81.assets import sanitize_entry
                for k,u,t,metadata in conn.execute('SELECT url_hash,url,downloaded_at,'+('metadata' if has_metadata else "'{}'")+' FROM js_cache'):
                    if policy.reason(u): continue
                    try:
                        value=json.loads(metadata or '{}'); value.update(url_hash=k,url=u,downloaded_at=t)
                        rows.append(sanitize_entry(value))
                    except (ValueError,KeyError,TypeError): continue
        finally: conn.close()
    private_write(args.output,''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows))

if __name__=='__main__': main()
