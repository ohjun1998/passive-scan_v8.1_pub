"""Offline v8.5 review batches. Immutable packets/results, verified resume and explicit gaps."""
import copy
import hashlib
import json
import time
import os
from functools import wraps
from collections import defaultdict,Counter
from pathlib import Path
from .core import Scope,digest,private_write,invalid_json_constant
from .ai_review import read_bytes,load_json,verify_packet,validate_result,render_review,_json,_publish,_no_duplicates
from .review_evidence import expand_record,group_key,authority_links,SCHEMA85

MAX_PACKETS=200
MAX_TOTAL_BYTES=8*1024*1024


def serialized(function):
    @wraps(function)
    def invoke(directory,*args,**kwargs):
        lock=Path(directory)/'.review-write.lock'
        try: fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError: raise ValueError('Another batch writer is running') from None
        try: return function(directory,*args,**kwargs)
        finally:
            os.close(fd);lock.unlink(missing_ok=True)
    return invoke


def source(report):
    report=Path(report).resolve();receipts={};content={}
    for name in ('requests.jsonl','analysis.json'):
        data=read_bytes(report/name);receipts[name]=hashlib.sha256(data).hexdigest();content[name]=data
    manifest=load_json(report/'manifest.json') if (report/'manifest.json').exists() else None
    if manifest and any(manifest.get('files',{}).get(n)!=v for n,v in receipts.items()):raise ValueError('Source report changed')
    records=[json.loads(line,parse_constant=invalid_json_constant,object_pairs_hook=_no_duplicates)
             for line in content['requests.jsonl'].decode().splitlines() if line.strip()]
    if len({r['observation_id'] for r in records})!=len(records):raise ValueError('Duplicate source evidence IDs')
    return records,receipts,manifest


def prepare_batch(report,output,patterns,authority=None,max_records=12,max_bytes=65536,body_bytes=6144):
    from .codex_review import make_prompt
    if not 2<=max_records<=100 or not 16384<=max_bytes<=250000 or not 1024<=body_bytes<=8192:
        raise ValueError('Invalid batch budget')
    records,receipts,manifest=source(report);scope=Scope(patterns)
    scoped=[r for r in records if scope.allows(r['url'])]
    links,supports=authority_links(scoped,authority,scope)
    grouped=defaultdict(list)
    for record in scoped:
        for fragment in expand_record(record,scope,body_bytes):
            fragment['authority']=links.get(record['observation_id'],{'identity':None,'policy':None,'policy_status':'not_provided'})
            grouped[group_key(record)].append(fragment)
    packets=[];total=0
    def make_packet(group,work):
        selected={r['observation_id']:r for r in work}
        for r in work:
            identity=(r.get('authority') or {}).get('identity')
            if identity and identity['observation_id'] not in selected:
                support=copy.deepcopy(supports[identity['observation_id']]);support['authority']=links.get(support['observation_id'],{})
                selected[support['observation_id']]=support
        return {'schema_version':'8.5','source_run_id':manifest.get('run_id') if manifest else None,
                'source_manifest_verified':manifest is not None,'source_receipts':receipts,'scope':{'patterns':scope.patterns},
                'evidence_trust':'untrusted_captured_data','network_requests_sent':0,'group':group,
                'batch_context':{'scoped_records':len(scoped),'work_records':len(work),'coverage':'partial_resource_group'},
                'budget':{'max_records':max_records,'max_bytes':max_bytes,'body_max_bytes':body_bytes},
                'evidence':list(selected.values()),'analysis':{},
                'omissions':{'out_of_scope':len(records)-len(scoped),'records':0,
                    'partial_bodies':sum(not b.get('complete',False) for r in selected.values()
                                        for b in [r['body'],(r.get('response') or {}).get('body') or {}])},
                'notice':'Split evidence is partial. Identity is a saved-response link, not cryptographic session verification. Policies are declared with provenance. Never mark reproduction confirmed.'}
    def fits(packet):
        return len(packet['evidence'])<=max_records and len(_json(dict(packet,packet_id='0'*64)).encode())<=max_bytes
    def flush(group,work):
        nonlocal total
        if not work:return
        packet=make_packet(group,work)
        if not fits(packet):raise ValueError('A fragment and required identity evidence exceed packet budget')
        packet['packet_id']=digest(packet);size=len(_json(packet).encode());total+=size
        if len(packets)>=MAX_PACKETS or total>MAX_TOTAL_BYTES:raise ValueError('Batch limit exceeded; select a smaller scope or report')
        packets.append(packet)
    for group,parts in sorted(grouped.items()):
        work=[]
        for part in parts:
            if work and (part['observation_id'] in {r['observation_id'] for r in work} or not fits(make_packet(group,work+[part]))):
                flush(group,work);work=[]
            work.append(part)
        flush(group,work)
    if not packets:raise ValueError('No in-scope evidence')
    index={'schema_version':'8.5','source_run_id':manifest.get('run_id') if manifest else None,'source_receipts':receipts,
        'authority_configuration_sha256':digest(authority) if authority else None,
        'scope':scope.patterns,'out_of_scope_records':len(records)-len(scoped),'selected_records':len(scoped),
        'packets':[{'packet_id':p['packet_id'],'group':p['group'],
                    'work':[{'observation_id':r['observation_id'],'fragment_id':r['fragment']['id'],'fragment_index':r['fragment']['index'],
                             'fragment_count':r['fragment']['count'],'observed':r['observed']} for r in p['evidence'] if not r['fragment'].get('support_only')]}
                   for p in packets],
        'records':[{'observation_id':r['observation_id'],'url':r['url'],'method':r['method'],'observed':r['observed'],
                    'human_finding_state':r.get('review',{}).get('state','captured' if r['observed'] else 'discovered')} for r in scoped]}
    index['batch_id']=digest(index);files={'batch.json':_json(index)}
    for packet in packets:
        prefix='packets/'+packet['packet_id']+'/'
        files.update({prefix+'packet.json':_json(packet),prefix+'schema.json':_json(SCHEMA85),prefix+'prompt.txt':make_prompt(packet)})
    _publish(output,files);refresh(output)
    return index


def verify_batch(directory):
    directory=Path(directory);index=load_json(directory/'batch.json',8*1024*1024)
    value=dict(index);claimed=value.pop('batch_id',None)
    if index.get('schema_version')!='8.5' or digest(value)!=claimed:raise ValueError('Batch index changed')
    if not 1<=len(index['packets'])<=MAX_PACKETS:raise ValueError('Invalid packet count')
    # Base manifest is immutable; progress.json/coverage.json are derived and never trusted for resume.
    manifest=load_json(directory/'manifest.json')
    if manifest['files'].get('batch.json')!=hashlib.sha256(read_bytes(directory/'batch.json')).hexdigest():raise ValueError('Batch receipt mismatch')
    seen=set()
    for spec in index['packets']:
        pid=spec['packet_id']
        if not isinstance(pid,str) or not __import__('re').fullmatch('[a-f0-9]{64}',pid) or pid in seen:raise ValueError('Invalid packet reference')
        seen.add(pid);name='packets/'+pid+'/packet.json'
        packet=verify_packet(load_json(directory/name,250000))
        if packet['packet_id']!=pid or packet['source_receipts']!=index['source_receipts']:raise ValueError('Packet source mismatch')
        for suffix in ('packet.json','schema.json','prompt.txt'):
            name='packets/'+pid+'/'+suffix
            if manifest['files'].get(name)!=hashlib.sha256(read_bytes(directory/name)).hexdigest():raise ValueError('Prepared file changed')
        expected={(r['observation_id'],r['fragment']['id']) for r in packet['evidence'] if not r['fragment'].get('support_only')}
        if expected!={(r['observation_id'],r['fragment_id']) for r in spec['work']}:raise ValueError('Work coverage mismatch')
    return index


def packet_at(directory,pid):
    index=verify_batch(directory)
    if pid not in {p['packet_id'] for p in index['packets']}:raise ValueError('Packet is not in this batch')
    return load_json(Path(directory)/'packets'/pid/'packet.json',250000)


def _accepted(directory,pid,packet):
    result_dir=Path(directory)/'results'/pid
    if not result_dir.exists():return None
    manifest=load_json(result_dir/'manifest.json')
    for name in ('packet.json','ai_review.json','execution.json','citations.json'):
        if manifest['files'].get(name)!=hashlib.sha256(read_bytes(result_dir/name)).hexdigest():raise ValueError('Accepted result changed')
    saved=verify_packet(load_json(result_dir/'packet.json',250000))
    if saved!=packet:raise ValueError('Accepted packet differs')
    result=validate_result(load_json(result_dir/'ai_review.json'),packet)
    return result


@serialized
def import_packet(directory,pid,result_path):
    packet=packet_at(directory,pid);result=validate_result(load_json(result_path),packet)
    existing=_accepted(directory,pid,packet)
    if existing is not None:
        if existing!=result:raise ValueError('Existing result differs; prepare a new batch')
    else:render_review(packet,result,Path(directory)/'results'/pid,{'provider':'manual_import','status':'imported','model_execution_verified':False})
    return refresh(directory)


def refresh(directory):
    directory=Path(directory);index=verify_batch(directory);parts=defaultdict(set);reviewed=defaultdict(set);validated=defaultdict(set);statuses=[];reviews=[]
    for spec in index['packets']:
        pid=spec['packet_id'];packet=load_json(directory/'packets'/pid/'packet.json',250000)
        result=_accepted(directory,pid,packet)
        if result:
            cited={c['observation_id'] for r in result['reviews'] for c in r['citations']}
            linked={oid for r in result['reviews'] for oid in r['observation_ids']}
            reviews.extend(dict(r,packet_id=pid) for r in result['reviews'])
        else:cited=set();linked=set()
        for work in spec['work']:
            oid=work['observation_id'];fid=work['fragment_id'];parts[oid].add(fid)
            if oid in linked:reviewed[oid].add(fid)
            if oid in cited:validated[oid].add(fid)
        attempts_path=directory/'attempts'/pid/'history.json'
        attempts=load_json(attempts_path) if attempts_path.exists() else []
        statuses.append({'packet_id':pid,'status':'completed' if result is not None else 'failed' if attempts and attempts[-1]['status']=='failed' else 'pending',
                         'attempt_count':len(attempts)})
    rows=[]
    for record in index['records']:
        oid=record['observation_id'];count=len(parts[oid]);done=len(reviewed[oid]);valid=len(validated[oid])
        rows.append(dict(record,stage='evidence_validated' if valid==count and count else 'ai_reviewed' if done==count and count else 'partially_reviewed' if done else 'captured' if record['observed'] else 'discovered',
                         fragments=count,reviewed_fragments=done,citation_validated_fragments=valid,reproduction_verified=False))
    result={'schema_version':'8.5','batch_id':index['batch_id'],'packets':statuses,'records':rows,
            'summary':{'records':len(rows),'packets':len(statuses),'completed_packets':sum(s['status']=='completed' for s in statuses),
                       'stages':dict(Counter(r['stage'] for r in rows)),'reproduction_verified':0},
            'notice':'A matched citation proves location/excerpt only. Human confirmation and reproduction are separate.'}
    private_write(directory/'progress.json',_json({'batch_id':index['batch_id'],'packets':statuses}))
    private_write(directory/'coverage.json',_json(result))
    private_write(directory/'aggregate.json',_json({'schema_version':'8.5','batch_id':index['batch_id'],'reviews':reviews,'coverage':result}))
    return result


@serialized
def run_batch(directory,timeout=300,model=None,retry_failed=False,max_attempts=3):
    from .codex_review import execute_packet,ReviewFailure
    directory=Path(directory);index=verify_batch(directory)
    if not 1<=max_attempts<=3:raise ValueError('Invalid attempt cap')
    for spec in index['packets']:
        pid=spec['packet_id'];packet=load_json(directory/'packets'/pid/'packet.json',250000)
        if _accepted(directory,pid,packet) is not None:continue
        history_path=directory/'attempts'/pid/'history.json'
        history=load_json(history_path) if history_path.exists() else []
        if history and not retry_failed:continue
        if len(history)>=max_attempts:continue
        started=time.monotonic()
        attempt={'number':len(history)+1,'status':'started','stage':'preflight','stage_history':[{'stage':'preflight','elapsed_seconds':0}],
                 'events':[],'target_requests_sent':0}
        history.append(attempt);private_write(history_path,_json(history))
        def progress(stage,event=None):
            attempt['stage']=stage
            if attempt['stage_history'][-1]['stage']!=stage and len(attempt['stage_history'])<50:
                attempt['stage_history'].append({'stage':stage,'elapsed_seconds':round(time.monotonic()-started,3)})
            if event and len(attempt['events'])<200:attempt['events'].append(event)
            private_write(history_path,_json(history))
        try:
            result,execution=execute_packet(packet,timeout,model,progress)
            render_review(packet,result,directory/'results'/pid,execution)
            attempt.update(status='completed',stage='published')
        except (ValueError,OSError,KeyError,TypeError,RecursionError) as error:
            attempt.update(status='failed',stage=error.stage if isinstance(error,ReviewFailure) else attempt['stage'],
                           code=error.code if isinstance(error,ReviewFailure) else 'RESULT_OR_IO_INVALID',
                           exception_type=type(error).__name__)
            # Do not continue network calls after a connection/auth/rate-limit failure.
            private_write(history_path,_json(history));refresh(directory);break
        private_write(history_path,_json(history));refresh(directory)
    return refresh(directory)
