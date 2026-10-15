#!/usr/bin/env python3
"""Opt-in, paced scoped JS downloads with persistent cache and run-wide budgets."""
import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path
from recon81.core import Scope, private_write, safe_url
from recon81.network_policy import NetworkPolicy
from recon81.guard import RunGuard, ProtectedHTTP, GuardStopped
from recon81.assets import AssetCache, cache_db_path, reusable

LIMIT = 2*1024*1024


def cached_keys(path, ttl=7*86400):
    if not Path(path).exists() and not cache_db_path(path).exists():
        return set()
    with AssetCache(path) as store:
        return store.fresh_keys(time.time(), ttl)


def download(urls, client, policy, output, mapping, cache, max_files=100, min_free_bytes=256*1024*1024,analyzer_version=None,revalidate=False):
    with AssetCache(cache) as store:
        return _download(urls, client, policy, output, mapping, store, max_files, min_free_bytes, analyzer_version, revalidate)


def _download(urls, client, policy, output, mapping, store, max_files, min_free_bytes, analyzer_version, revalidate):
    output.mkdir(parents=True,exist_ok=True)
    known=store.fresh_keys(time.time())
    rows=[]
    downloaded=0
    for url in sorted(set(urls)):
        key=hashlib.sha256(url.encode()).hexdigest()
        if policy.reason(url) or not url.split('?',1)[0].lower().endswith('.js'):
            continue
        previous=store.get(key, include_records=False) or {}
        cached=analyzer_version is None or reusable(previous,analyzer_version)
        if key in known and cached and not revalidate:
            if analyzer_version: rows.append(key+'.js\t'+safe_url(url))
            continue
        if downloaded >= max_files:
            break
        if shutil.disk_usage(output).free < min_free_bytes:
            break
        try:
            conditional={}
            if revalidate and cached:
                if previous.get('etag') and '[REDACTED]' not in previous['etag']: conditional['If-None-Match']=previous['etag']
                elif previous.get('last_modified'): conditional['If-Modified-Since']=previous['last_modified']
            response=client.fetch(url,headers=conditional,limit=LIMIT) if conditional else client.get(url,LIMIT)
        except GuardStopped as error:
            if 'budget_exhausted' in str(error):
                break
            raise
        if response['status']==304 and cached and previous:
            previous['downloaded_at']=time.time(); store.put_download(previous)
            rows.append(key+'.js\t'+safe_url(url)); continue
        if response['status']!=200 or not response['complete']:
            continue
        name=key+'.js'
        target=output/name
        with open(target,'wb') as stream:
            stream.write(response['body'])
        target.chmod(0o600)
        rows.append(name+'\t'+safe_url(url))
        item={'url_hash':key,'url':safe_url(url),'downloaded_at':time.time(),'content_hash':hashlib.sha256(response['body']).hexdigest()}
        headers=response.get('headers') or {}
        for field,header in [('etag','etag'),('last_modified','last-modified')]:
            value=next((v for k,v in headers.items() if k.lower()==header),'')
            if value: item[field]=value
        store.put_download(item)
        known.add(key)
        downloaded+=1
    private_write(mapping,'\n'.join(rows)+ ('\n' if rows else ''))
    return downloaded


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--urls',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mapping',type=Path,required=True)
    p.add_argument('--scope',action='append',required=True)
    p.add_argument('--state',type=Path,default=Path('results/active_guard.sqlite3'))
    p.add_argument('--cache',type=Path,default=Path('results/js_download_cache.jsonl'))
    p.add_argument('--active',action='store_true')
    p.add_argument('--analyzer-version',help='Require matching cached JS analysis, not only download history')
    p.add_argument('--revalidate',action='store_true',help='One conditional request per cached URL; never an automatic retry')
    args=p.parse_args()
    if not args.active:
        p.error('Target downloads require --active')
    policy=NetworkPolicy(Scope(args.scope))
    guard=RunGuard(args.state)
    try:
        # This counter is shared across all domains processed by this worker.
        counter=args.state.with_suffix('.download-count')
        used=int(counter.read_text()) if counter.exists() else 0
        count=download(args.urls.read_text(encoding='utf-8').splitlines(),ProtectedHTTP(policy,guard),policy,args.output,args.mapping,args.cache,max_files=max(0,100-used),analyzer_version=args.analyzer_version,revalidate=args.revalidate)
        private_write(counter,str(used+count))
        print('Downloaded JS files: '+str(count))
    except GuardStopped:
        print('JS downloads stopped by overload protection; no automatic retry.')
        return 3
    finally:
        guard.close()
    return 0

if __name__=='__main__':
    raise SystemExit(main())
