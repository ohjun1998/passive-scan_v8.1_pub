"""Offline v8.5 review batches. Immutable packets/results, verified resume and explicit gaps."""
import copy
import hashlib
import json
import time
from functools import wraps
from collections import defaultdict,Counter
from pathlib import Path
from .core import Scope,digest,private_write,invalid_json_constant,sanitize_value,safe_url
from .ai_review import (read_bytes,load_json,verify_packet,validate_result,render_review,_json,_publish,_no_duplicates,
                        bounded_json,validate_source_manifest,RESULT_LIMIT,AGGREGATE_LIMIT)
from .review_evidence import expand_record,group_key,authority_links,SCHEMA85
from .locking import advisory_file_lock

MAX_PACKETS=200
MAX_TOTAL_BYTES=8*1024*1024


def serialized(function):
    @wraps(function)
    def invoke(directory,*args,**kwargs):
        lock=Path(directory)/'.review-write.lock'
        with advisory_file_lock(lock,'Another batch writer is running'):
            return function(directory,*args,**kwargs)
    return invoke


def source(report, include_analysis=False):
    report=Path(report).resolve();receipts={};content={}
    for name in ('requests.jsonl','analysis.json'):
        data=read_bytes(report/name);receipts[name]=hashlib.sha256(data).hexdigest();content[name]=data
    manifest_path=report/'manifest.json'
    manifest=load_json(manifest_path) if manifest_path.exists() or manifest_path.is_symlink() else None
    if manifest is not None:validate_source_manifest(manifest,receipts)
    elif manifest_path.exists():raise ValueError('Invalid source manifest')
    records=[json.loads(line,parse_constant=invalid_json_constant,object_pairs_hook=_no_duplicates)
             for line in content['requests.jsonl'].decode().splitlines() if line.strip()]
    if len({r['observation_id'] for r in records})!=len(records):raise ValueError('Duplicate source evidence IDs')
    if include_analysis:
        analysis=json.loads(content['analysis.json'],parse_constant=invalid_json_constant,object_pairs_hook=_no_duplicates)
        if not isinstance(analysis,dict):raise ValueError('Invalid source analysis')
        return records,receipts,manifest,analysis
    return records,receipts,manifest


def prepare_batch(report,output,patterns,authority=None,max_records=12,max_bytes=65536,body_bytes=6144):
    from .codex_review import make_prompt
    from .analysis import comparison_selector
    if not 2<=max_records<=100 or not 16384<=max_bytes<=250000 or not 1024<=body_bytes<=8192:
        raise ValueError('Invalid batch budget')
    records,receipts,manifest=source(report);scope=Scope(patterns)
    scoped=[r for r in records if scope.allows(r['url'])]
    links,supports=authority_links(scoped,authority,scope)
    # Keep source records lazy. Expanding every body before enforcing the batch cap
    # multiplied memory and hashing work for inputs which could never fit.
    grouped=defaultdict(list);selectors={}
    for record in scoped:
        selector=comparison_selector(record)
        # Scenario labels may differ between owner/denial controls of the same
        # saved request. Keep labels in evidence without splitting those controls.
        key=(group_key(dict(record,context={})),selector['key'])
        grouped[key].append(record)
        previous=selectors.get(key)
        if previous:
            selector=dict(selector,uncertain=previous['uncertain'] or selector['uncertain'],
                          uncertainty_reasons=sorted(set(previous['uncertainty_reasons'])|set(selector['uncertainty_reasons'])))
        selectors[key]=selector
    packets=[];total=0
    def make_packet(key,work):
        selected={r['observation_id']:r for r in work}
        for r in work:
            identity=(r.get('authority') or {}).get('identity')
            if identity and identity['observation_id'] not in selected:
                support=copy.deepcopy(supports[identity['observation_id']]);support['authority']=links.get(support['observation_id'],{})
                selected[support['observation_id']]=support
        whole=len(work)==len(grouped[key]) and all(r['fragment']['count']==1 for r in work)
        comparison={'resource_key':key[1],'saved_observations':len(grouped[key]),'included_observations':len(work),
                    'missing_observations':len(grouped[key])-len(work),
                    'coverage':'complete_saved_group' if whole else 'partial_saved_group',
                    'resource_equivalence':'unverified' if selectors[key]['uncertain'] else 'matching_saved_selectors',
                    'uncertainty_reasons':selectors[key]['uncertainty_reasons']}
        return {'schema_version':'8.5','source_run_id':sanitize_value(manifest.get('run_id')) if manifest is not None else None,
                'source_manifest_verified':manifest is not None,'source_receipts':receipts,'scope':{'patterns':scope.patterns},
                'evidence_trust':'untrusted_captured_data','network_requests_sent':0,'group':key[0],
                'comparison_context':comparison,
                'batch_context':{'scoped_records':len(scoped),'work_records':len(work),'coverage':comparison['coverage']},
                'budget':{'max_records':max_records,'max_bytes':max_bytes,'body_max_bytes':body_bytes},
                'evidence':list(selected.values()),'analysis':{},
                'omissions':{'out_of_scope':len(records)-len(scoped),'records':comparison['missing_observations'],
                    'partial_bodies':sum(not b.get('complete',False) for r in selected.values()
                                        for b in [r['body'],(r.get('response') or {}).get('body') or {}])},
                'notice':'Only saved comparison candidates are grouped. Split groups/fragments are partial; masked selectors do not establish resource equality. Identity is a saved-response link, not session verification. Policies are declarations. Never mark reproduction confirmed.'}
    def fits(packet):
        return len(packet['evidence'])<=max_records and len(_json(dict(packet,packet_id='0'*64)).encode())<=max_bytes
    def flush(key,work):
        nonlocal total
        if not work:return
        packet=make_packet(key,work)
        if not fits(packet):raise ValueError('A fragment and required identity evidence exceed packet budget')
        packet['packet_id']=digest(packet);size=len(_json(packet).encode())
        if len(packets)>=MAX_PACKETS or total+size>MAX_TOTAL_BYTES:raise ValueError('Batch limit exceeded; select a smaller scope or report')
        total+=size;packets.append(packet)
    def order(record):
        context=record.get('context') or {};link=links.get(record['observation_id']) or {}
        policy=link.get('policy') or {};identity=link.get('identity') or {}
        actor=context.get('actor','');expected=policy.get('expected_access',context.get('expected_access','unknown'))
        # Interleave owner, another actor, administrative and denial controls before
        # consuming another fragment of a large response from any one actor.
        role=str(identity.get('observed_role','')).lower();status=(record.get('response') or {}).get('status',0)
        category=0 if actor and actor==policy.get('owner') else 2 if 'admin' in role else 3 if status in (401,403,404) else 1 if expected=='deny' else 4
        return category,sanitize_value(actor),record['observation_id']
    for key,group_records in sorted(grouped.items()):
        iterators=[iter(expand_record(r,scope,body_bytes,MAX_PACKETS)) for r in sorted(group_records,key=order)]
        while iterators:
            work=[];remaining=[]
            for iterator in iterators:
                try:part=next(iterator)
                except StopIteration:continue
                part['authority']=links.get(part['observation_id'],{'identity':None,'policy':None,'policy_status':'not_provided'})
                if work and not fits(make_packet(key,work+[part])):
                    flush(key,work);work=[]
                work.append(part);remaining.append(iterator)
                if len(packets)>=MAX_PACKETS:raise ValueError('Batch limit exceeded; select a smaller scope or report')
            flush(key,work);iterators=remaining
    if not packets:raise ValueError('No in-scope evidence')
    index={'schema_version':'8.5','source_run_id':sanitize_value(manifest.get('run_id')) if manifest is not None else None,'source_receipts':receipts,
        'authority_configuration_sha256':digest(authority) if authority else None,
        'scope':scope.patterns,'out_of_scope_records':len(records)-len(scoped),'selected_records':len(scoped),
        'packets':[{'packet_id':p['packet_id'],'group':p['group'],'comparison_context':p['comparison_context'],
                    'work':[{'observation_id':r['observation_id'],'fragment_id':r['fragment']['id'],'fragment_index':r['fragment']['index'],
                             'fragment_count':r['fragment']['count'],'observed':r['observed']} for r in p['evidence'] if not r['fragment'].get('support_only')]}
                   for p in packets],
        'records':[{'observation_id':r['observation_id'],'url':safe_url(r['url']),'method':sanitize_value(r['method']),'observed':r['observed'],
                    'human_finding_state':sanitize_value(r.get('review',{}).get('state','captured' if r['observed'] else 'discovered'))} for r in scoped]}
    index['batch_id']=digest(index);files={'batch.json':bounded_json(index,MAX_TOTAL_BYTES)}
    for packet in packets:
        prefix='packets/'+packet['packet_id']+'/'
        files.update({prefix+'packet.json':_json(packet),prefix+'schema.json':_json(SCHEMA85),prefix+'prompt.txt':make_prompt(packet)})
    _publish(output,files);refresh(output)
    return index


def _signature(path):
    stat=Path(path).stat()
    return stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns


def _remember(tracked,path):
    tracked[Path(path)]=_signature(path)


def _assert_unchanged(state):
    # Hashes are checked on entry. Stat identity/ctime guards cached, immutable files
    # during this locked run; subsequent commands always perform full hash validation.
    for path,expected in state['tracked'].items():
        if path.is_symlink() or _signature(path)!=expected:
            raise ValueError('Verified batch or result changed during execution')


def _verified_read(directory,name,manifest,tracked,limit=MAX_TOTAL_BYTES):
    relative=Path(name)
    if relative.is_absolute() or '..' in relative.parts:raise ValueError('Invalid receipt path')
    path=Path(directory)/relative
    before=_signature(path);data=read_bytes(path,limit)
    if hashlib.sha256(data).hexdigest()!=manifest['files'].get(name):raise ValueError('Prepared or accepted file changed')
    _remember(tracked,path)
    if tracked[path]!=before:raise ValueError('File changed while verifying')
    return data


def _loads(data):
    return json.loads(data,parse_constant=invalid_json_constant,object_pairs_hook=_no_duplicates)


def _prepared(directory):
    directory=Path(directory);tracked={}
    manifest=load_json(directory/'manifest.json');_remember(tracked,directory/'manifest.json')
    if not isinstance(manifest,dict) or not isinstance(manifest.get('files'),dict):raise ValueError('Invalid batch manifest')
    index=_loads(_verified_read(directory,'batch.json',manifest,tracked))
    value=dict(index);claimed=value.pop('batch_id',None)
    if index.get('schema_version')!='8.5' or digest(value)!=claimed:raise ValueError('Batch index changed')
    if not 1<=len(index['packets'])<=MAX_PACKETS:raise ValueError('Invalid packet count')
    packets={}
    for spec in index['packets']:
        pid=spec['packet_id']
        if not isinstance(pid,str) or not __import__('re').fullmatch('[a-f0-9]{64}',pid) or pid in packets:raise ValueError('Invalid packet reference')
        prefix='packets/'+pid+'/'
        packet=verify_packet(_loads(_verified_read(directory,prefix+'packet.json',manifest,tracked,250000)))
        if packet['packet_id']!=pid or packet['source_receipts']!=index['source_receipts']:raise ValueError('Packet source mismatch')
        for suffix in ('schema.json','prompt.txt'):_verified_read(directory,prefix+suffix,manifest,tracked)
        expected={(r['observation_id'],r['fragment']['id']) for r in packet['evidence'] if not r['fragment'].get('support_only')}
        if expected!={(r['observation_id'],r['fragment_id']) for r in spec['work']}:raise ValueError('Work coverage mismatch')
        if spec.get('comparison_context')!=packet.get('comparison_context'):raise ValueError('Comparison coverage mismatch')
        packets[pid]=packet
    return {'index':index,'packets':packets,'tracked':tracked,'results':{},'attempts':{}}


def verify_batch(directory):
    return _prepared(directory)['index']


def packet_at(directory,pid):
    state=_prepared(directory)
    if pid not in state['packets']:raise ValueError('Packet is not in this batch')
    return state['packets'][pid]


def _accepted(directory,pid,packet,tracked=None):
    result_dir=Path(directory)/'results'/pid
    if not result_dir.exists():return None
    if result_dir.is_symlink() or not result_dir.is_dir():raise ValueError('Invalid accepted result directory')
    # A crash between exclusive mkdir and the atomic directory rename leaves only
    # an empty reservation. It contains no accepted evidence and is safe to retry.
    if not any(result_dir.iterdir()):
        result_dir.rmdir();return None
    tracked=tracked if tracked is not None else {}
    manifest=load_json(result_dir/'manifest.json');_remember(tracked,result_dir/'manifest.json')
    required={'packet.json','ai_review.json','execution.json','citations.json','review.md','index.html'}
    if not isinstance(manifest,dict) or not isinstance(manifest.get('files'),dict) or not required<=set(manifest['files']):
        raise ValueError('Incomplete accepted result')
    files={name:_verified_read(result_dir,name,manifest,tracked,RESULT_LIMIT if name=='ai_review.json' else AGGREGATE_LIMIT)
           for name in manifest['files']}
    saved=verify_packet(_loads(files['packet.json']))
    if saved!=packet:raise ValueError('Accepted packet differs')
    return validate_result(_loads(files['ai_review.json']),packet)


def _state(directory):
    state=_prepared(directory)
    for pid,packet in state['packets'].items():
        state['results'][pid]=_accepted(directory,pid,packet,state['tracked'])
        path=Path(directory)/'attempts'/pid/'history.json'
        state['attempts'][pid]=load_json(path) if path.exists() else []
    return state


def _snapshot(state,prospective=None):
    index=state['index'];parts=defaultdict(set);reviewed=defaultdict(set);validated=defaultdict(set);statuses=[];reviews=[]
    comparison_counts=Counter()
    for spec in index['packets']:
        pid=spec['packet_id'];result=prospective[1] if prospective and prospective[0]==pid else state['results'].get(pid)
        if result is not None:
            cited={c['observation_id'] for r in result['reviews'] for c in r['citations']}
            linked={oid for r in result['reviews'] for oid in r['observation_ids']}
            reviews.extend(dict(r,packet_id=pid) for r in result['reviews'])
        else:cited=set();linked=set()
        for work in spec['work']:
            oid=work['observation_id'];fid=work['fragment_id'];parts[oid].add(fid)
            if oid in linked:reviewed[oid].add(fid)
            if oid in cited:validated[oid].add(fid)
        attempts=state['attempts'].get(pid,[])
        comparison=spec.get('comparison_context',{'coverage':'legacy_unrecorded','resource_equivalence':'unverified'})
        comparison_counts[comparison['coverage']]+=1
        statuses.append({'packet_id':pid,'status':'completed' if result is not None else 'failed' if attempts and attempts[-1]['status']=='failed' else 'pending',
                         'attempt_count':len(attempts),'comparison_context':comparison})
    rows=[]
    for record in index['records']:
        oid=record['observation_id'];count=len(parts[oid]);done=len(reviewed[oid]);valid=len(validated[oid])
        rows.append(dict(record,stage='evidence_validated' if valid==count and count else 'ai_reviewed' if done==count and count else 'partially_reviewed' if done else 'captured' if record['observed'] else 'discovered',
                         fragments=count,reviewed_fragments=done,citation_validated_fragments=valid,reproduction_verified=False))
    coverage={'schema_version':'8.5','batch_id':index['batch_id'],'packets':statuses,'records':rows,
            'summary':{'records':len(rows),'packets':len(statuses),'completed_packets':sum(s['status']=='completed' for s in statuses),
                       'stages':dict(Counter(r['stage'] for r in rows)),'comparison_packets':dict(comparison_counts),'reproduction_verified':0},
            'notice':'A matched citation proves location/excerpt only. Comparison coverage refers only to the saved group; split groups are partial and uncertain selectors do not prove resource equality. Human confirmation and reproduction are separate.'}
    aggregate={'schema_version':'8.5','batch_id':index['batch_id'],'reviews':reviews,'coverage':coverage}
    return coverage,bounded_json(aggregate,AGGREGATE_LIMIT)


def _refresh(directory,state=None):
    directory=Path(directory);state=state if state is not None else _state(directory)
    _assert_unchanged(state)
    result,aggregate=_snapshot(state)
    private_write(directory/'progress.json',_json({'batch_id':state['index']['batch_id'],'packets':result['packets']}))
    private_write(directory/'coverage.json',bounded_json(result,AGGREGATE_LIMIT))
    private_write(directory/'aggregate.json',aggregate)
    return result


@serialized
def refresh(directory):
    return _refresh(directory)


def _publish_result(directory,pid,packet,result,execution,state):
    # Fail before committing immutable results if either its persisted form or the
    # resulting aggregate cannot be reopened by the report/evaluation pipeline.
    bounded_json(result)
    _snapshot(state,(pid,result))
    _assert_unchanged(state)
    render_review(packet,result,Path(directory)/'results'/pid,execution)
    state['results'][pid]=_accepted(directory,pid,packet,state['tracked'])


@serialized
def import_packet(directory,pid,result_path):
    state=_state(directory)
    if pid not in state['packets']:raise ValueError('Packet is not in this batch')
    packet=state['packets'][pid];result=validate_result(load_json(result_path),packet)
    existing=state['results'][pid]
    if existing is not None:
        if existing!=result:raise ValueError('Existing result differs; prepare a new batch')
    else:_publish_result(directory,pid,packet,result,{'provider':'manual_import','status':'imported','model_execution_verified':False},state)
    return _refresh(directory,state)


@serialized
def run_batch(directory,timeout=300,model=None,retry_failed=False,max_attempts=3,first_response_timeout=180):
    from .codex_review import execute_packet,ReviewFailure,_execution_settings,configuration_session,DEFAULT_MODEL,DEFAULT_REASONING_EFFORT
    model=DEFAULT_MODEL if model is None else model
    directory=Path(directory)
    if not 1<=max_attempts<=3:raise ValueError('Invalid attempt cap')
    _execution_settings(timeout,model,first_response_timeout)
    state=_state(directory)
    with configuration_session():
        for spec in state['index']['packets']:
            pid=spec['packet_id'];packet=state['packets'][pid]
            if state['results'][pid] is not None:continue
            history=state['attempts'][pid]
            if history and not retry_failed:continue
            if len(history)>=max_attempts:continue
            _assert_unchanged(state)
            history_path=directory/'attempts'/pid/'history.json'
            started=time.monotonic()
            attempt={'number':len(history)+1,'status':'started','stage':'preflight','stage_history':[{'stage':'preflight','elapsed_seconds':0}],
                     'events':[],'target_requests_sent':0,
                     'settings':{'timeout':timeout,'first_response_timeout':min(first_response_timeout,timeout),
                                 'requested_model':model,'requested_reasoning_effort':DEFAULT_REASONING_EFFORT}}
            history.append(attempt);private_write(history_path,_json(history))
            def progress(stage,event=None):
                attempt['stage']=stage
                if attempt['stage_history'][-1]['stage']!=stage and len(attempt['stage_history'])<50:
                    attempt['stage_history'].append({'stage':stage,'elapsed_seconds':round(time.monotonic()-started,3)})
                if event and len(attempt['events'])<200:attempt['events'].append(event)
                private_write(history_path,_json(history))
            try:
                result,execution=execute_packet(packet,timeout,model,progress,first_response_timeout)
                result=validate_result(result,packet)
                _publish_result(directory,pid,packet,result,execution,state)
                attempt.update(status='completed',stage='published')
            except (ValueError,OSError,KeyError,TypeError,RecursionError) as error:
                attempt.update(status='failed',stage=error.stage if isinstance(error,ReviewFailure) else attempt['stage'],
                               code=error.code if isinstance(error,ReviewFailure) else 'RESULT_OR_IO_INVALID',
                               exception_type=type(error).__name__)
                if isinstance(error,ReviewFailure) and error.diagnostic:attempt['diagnostic']=error.diagnostic
                private_write(history_path,_json(history));break
            private_write(history_path,_json(history))
            # History is durable per attempt. Full derived snapshots are rebuilt once
            # at the end; coverage can reconstruct them after an interrupted run.
    return _refresh(directory,state)
