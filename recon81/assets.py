"""Private JS analysis cache. Hashes and binary version distinguish analysis revisions."""
import hashlib
import json
import re
import math
from pathlib import Path
from .core import private_write,read_limited,safe_url,redact_text
from .context import attach_context
from .importers import native_record


def file_hash(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''): h.update(chunk)
    return h.hexdigest()


def sanitize_entry(item):
    if not isinstance(item,dict) or not re.fullmatch('[0-9a-f]{64}',str(item.get('url_hash',''))): raise ValueError('Invalid asset key')
    result={'url_hash':item['url_hash'],'url':safe_url(item['url']),'downloaded_at':float(item['downloaded_at'])}
    if not math.isfinite(result['downloaded_at']): raise ValueError('Invalid asset timestamp')
    if re.fullmatch('[0-9a-f]{64}',str(item.get('content_hash',''))): result['content_hash']=item['content_hash']
    for key in ('etag','last_modified'):
        value=str(item.get(key,''))
        if value and len(value)<=256 and '\r' not in value and '\n' not in value: result[key]=redact_text(value)
    analysis=item.get('analysis')
    if isinstance(analysis,dict) and re.fullmatch('[0-9a-f]{64}',str(analysis.get('content_hash',''))) and isinstance(analysis.get('records'),list):
        records=[]
        for r in analysis['records'][:500]:
            r=dict(r,observed=False,source='jsluice',origin_url=result['url'],response=None,context={})
            clean=native_record(r); records.append(clean)
        result['analysis']={'content_hash':analysis['content_hash'],'analyzer_version':redact_text(str(analysis.get('analyzer_version','')))[:128],'records':records,'total_records':max(len(records),int(analysis.get('total_records',len(records))))}
    return result


def entries(path):
    if not Path(path).exists(): return {}
    result={}
    for line in read_limited(path).decode('utf-8').splitlines():
        try:
            item=sanitize_entry(json.loads(line))
            if item['url_hash'] not in result or item['downloaded_at']>=result[item['url_hash']]['downloaded_at']: result[item['url_hash']]=item
        except (ValueError,KeyError,TypeError): continue
    return result


def write_entries(path,items):
    private_write(path,''.join(json.dumps(sanitize_entry(x),ensure_ascii=False)+'\n' for x in items.values()))


def signature(record): return record['method']+' '+record['url']+' '+','.join(sorted(record['body']['fields']))


def update_analysis(cache,key,content_hash,version,records):
    items=entries(cache)
    if key not in items: raise ValueError('Download metadata not found')
    item=items[key]; previous=item.get('analysis') or {}
    if item.get('content_hash')!=content_hash: raise ValueError('Asset content differs from download metadata')
    before={signature(r) for r in previous.get('records',[])}; after={signature(r) for r in records}
    kind='first_seen' if not previous else 'changed' if previous.get('content_hash')!=content_hash else 'reanalyzed' if previous.get('analyzer_version')!=version else 'unchanged'
    asset={'content_hash':content_hash,'analyzer_version':version,'change_kind':kind,'added_count':len(after-before),'removed_count':len(before-after),'delta_partial':previous.get('total_records',0)>len(previous.get('records',[])),'added_preview':[x[:512] for x in sorted(after-before)[:10]],'removed_preview':[x[:512] for x in sorted(before-after)[:10]],'reused':False}
    decorated=[]
    for record in records:
        r=dict(record,asset=asset,context={}); attach_context(r,{}); decorated.append(r)
    item['analysis']={'content_hash':content_hash,'analyzer_version':version,'records':decorated[:500],'total_records':len(records)}
    write_entries(cache,items)
    return decorated


def reusable(item,version):
    analysis=item.get('analysis') or {}
    return analysis.get('content_hash')==item.get('content_hash') and analysis.get('analyzer_version')==version and isinstance(analysis.get('records'),list)


def reuse_analysis(cache,mapping,version):
    items=entries(cache); output=[]
    if not Path(mapping).exists(): return []
    for line in Path(mapping).read_text().splitlines():
        if '\t' not in line: continue
        filename,url=line.split('\t',1); key=Path(filename).stem; item=items.get(key)
        if not item or item['url']!=safe_url(url) or not reusable(item,version): continue
        for record in item['analysis']['records']:
            r=native_record(record); r['asset']=dict(r.get('asset') or {},reused=True); output.append(r)
    return output
