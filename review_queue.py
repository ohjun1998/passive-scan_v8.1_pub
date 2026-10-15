#!/usr/bin/env python3
"""Build an offline review queue; execute explicitly selected read baselines only."""
import argparse
import json
import uuid
from urllib.parse import urlsplit
from pathlib import Path
from recon81.analysis import analyze
from recon81.core import Inventory,private_write,normalize_record,get_header,MASK,read_limited
from recon81.context import attach_context
from recon81.graphql_policy import read_only_graphql
from recon81.network_policy import NetworkPolicy,scope_from_file
from recon81.guard import RunGuard,ProtectedHTTP,GuardStopped


def executable(record,policy,read_post_urls=()):
    if not record['observed']: return False,'actual_request_required',None
    if policy.reason(record['url']): return False,'policy_blocked',None
    if MASK in record['url']: return False,'masked_url',None
    method=record['method']; body=record['body']
    if method in ('GET','HEAD'):
        if body['kind']!='empty': return False,'read_request_has_body',None
        return True,'read_baseline',None
    if method=='POST' and body['complete'] and body['kind'] in ('json','form','xml'):
        data=body['text'].encode()
        if MASK in body['text'] or len(data)>8192: return False,'masked_or_excessive_body',None
        if body['kind']=='json':
            payload=json.loads(data)
            query=payload.get('query') if isinstance(payload,dict) else None
            if isinstance(query,str):
                try:
                    from graphql import parse
                    parse(query,max_tokens=1000)
                    captured_headers={h['name']:h['value'] for h in record['headers']}
                    if policy.allows_graphql(record['url'],captured_headers,data): return True,'bounded_graphql_query',data
                    return False,'graphql_query_only',None
                except Exception:
                    if 'graphql' in urlsplit(record['url']).path.lower(): return False,'invalid_graphql',None
        if record['url'] in read_post_urls and record.get('context',{}).get('operation')=='read':
            return True,'explicit_read_post',data
    return False,'requires_manual_function_review',None


def build(records,policy):
    enriched,_=analyze(records); items=[]
    for r in enriched:
        if r['review']['state'] in ('confirmed','false_positive'): continue
        allowed,reason,_=executable(r,policy)
        items.append({'observation_id':r['observation_id'],'method':r['method'],'url':r['url'],'actor':r['context'].get('actor',''),'scenario':r['context'].get('scenario',''),'priority':r['triage']['priority'],'score':r['triage']['score'],'reasons':r['triage']['hints'],'baseline_eligible':allowed,'eligibility_reason':reason,'state':r['review']['state']})
    return {'schema_version':'8.2','purpose':'review_and_read_baseline_only','not_a_vulnerability_verdict':True,'items':items}


def execute(inventory,plan,ids,client,policy,actor,tenant='',headers=None,read_post_urls=(),expected='unknown'):
    if not ids or len(ids)>client.guard.max_requests: raise ValueError('Explicit selection must fit the run budget')
    if not actor: raise ValueError('An explicit actor label is required')
    from recon81.context import clean_context
    clean_context({'actor':actor,'tenant':tenant,'expected_access':expected})
    if plan.get('schema_version')!='8.2': raise ValueError('Invalid queue format')
    entries={item['observation_id']:item for item in plan['items']}
    records={r['observation_id']:r for r in inventory.records()}
    selections=[]
    # Validate every selected entry before any request; queue edits cannot replace DB evidence.
    for oid in dict.fromkeys(ids):
        if oid not in entries or oid not in records: raise ValueError('Unknown selected observation')
        record=records[oid]; entry=entries[oid]
        if entry['url']!=record['url'] or entry['method']!=record['method']: raise ValueError('Queue differs from inventory')
        if record['review']['state'] in ('confirmed','false_positive'): raise ValueError('Concluded observations are not executable')
        allowed,reason,data=executable(record,policy,read_post_urls)
        if not allowed: raise ValueError('Selection requires manual review: '+reason)
        outgoing={k:get_header(record['headers'],k) for k in ('Accept','Accept-Language','Content-Type') if get_header(record['headers'],k)}
        for key,value in (headers or {}).items():
            outgoing = {k:v for k,v in outgoing.items() if k.lower()!=key.lower()}
            outgoing[key] = value
        if any(MASK in str(v) for v in outgoing.values()): raise ValueError('Masked headers cannot be transmitted')
        if reason=='bounded_graphql_query' and not policy.allows_graphql(record['url'],outgoing,data):
            raise ValueError('Runtime GraphQL headers differ from the approved envelope')
        selections.append((record,data,outgoing))
    count=0; skipped=0; stopped=''; capture=uuid.uuid4().hex
    for original,data,outgoing in selections:
        try: result=client.fetch(original['url'],original['method'],outgoing,data,approved_read_post=original['method']=='POST')
        except GuardStopped as error:
            if str(error)=='costly_request_budget_exhausted':
                skipped+=1;inventory.review(original['observation_id'],'deferred','Costly endpoint request budget reached; other read baselines may continue.');continue
            stopped=str(error); break
        response={'status':result['status'],'headers':result['headers'],'body':result['body'] if result['complete'] else None}
        record=normalize_record(original['url'],original['method'],outgoing,data if data is not None else b'',response,source='validation_baseline')
        context={'actor':actor,'tenant':tenant,'scenario':original['context'].get('scenario',''),'capture_id':capture,'operation':'read','expected_access':expected,'parent_observation_id':original['observation_id']}
        inventory.add(attach_context(record,context)); count+=1
        inventory.review(original['observation_id'],'testing','Read baseline collected; this is not a vulnerability verdict.')
    return {'baselines_collected':count,'skipped_costly_budget':skipped,'stop_reason':stopped,'automatically_confirmed_vulnerabilities':0}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('build','execute'):
        cmd=sub.add_parser(name); cmd.add_argument('--db',type=Path,default=Path('reports/request_inventory.sqlite3'))
        cmd.add_argument('--scope-file',type=Path,required=True); cmd.add_argument('--queue',type=Path,default=Path('reports/review_queue.json'))
        cmd.add_argument('--graphql-url',action='append',default=[],help='Exact reviewed GraphQL endpoint; JSON query operations only')
        if name=='execute':
            cmd.add_argument('--id',action='append',required=True)
            cmd.add_argument('--actor',required=True); cmd.add_argument('--tenant',default='')
            cmd.add_argument('--expected-access',choices=['allow','deny','unknown'],default='unknown')
            cmd.add_argument('--headers-file',type=Path,help='Runtime-only JSON headers; credentials are never put into the queue')
            cmd.add_argument('--read-post-url',action='append',default=[],help='Exact URL, with captured operation=read label')
            cmd.add_argument('--max-requests',type=int,default=20)
            cmd.add_argument('--state',type=Path,default=Path('results/validation_guard.sqlite3'))
            cmd.add_argument('--active',action='store_true')
    args=p.parse_args(argv)
    if not args.db.is_file(): p.error('Inventory DB does not exist')
    policy=NetworkPolicy(scope_from_file(args.scope_file),graphql_urls=args.graphql_url)
    try:
        with Inventory(args.db) as inventory:
            if args.command=='build':
                records=[r for r in inventory.records() if policy.scope.allows(r['url'])]
                private_write(args.queue,json.dumps(build(records,policy),ensure_ascii=False,indent=2))
                print(json.dumps({'queue_items':len(records),'network_requests_sent':0}))
            else:
                if not args.active: p.error('Execution requires --active and explicit --id selections')
                if not 1<=args.max_requests<=100: p.error('--max-requests must be 1..100')
                from recon81.context import clean_context
                clean_context({'actor':args.actor,'tenant':args.tenant})
                headers=json.loads(read_limited(args.headers_file)) if args.headers_file else {}
                if not isinstance(headers,dict) or len(headers)>30 or any(not isinstance(k,str) or not isinstance(v,str) or len(v)>8192 or '\n' in k+v or '\r' in k+v for k,v in headers.items()): raise ValueError('Invalid runtime headers')
                # Only allow ordinary request headers. Proxy/transport controls are excluded.
                if any(k.lower() in ('host','proxy-authorization','content-length','transfer-encoding','connection') for k in headers): raise ValueError('Unsafe transport headers')
                guard=RunGuard(args.state,max_requests=args.max_requests,interval=1)
                try:
                    result=execute(inventory,json.loads(read_limited(args.queue)),args.id,ProtectedHTTP(policy,guard),policy,args.actor,args.tenant,headers,args.read_post_url,args.expected_access)
                    print(json.dumps(result)); return 3 if result['stop_reason'] and 'budget_exhausted' not in result['stop_reason'] else 0
                finally: guard.close()
        return 0
    except (ValueError,KeyError,TypeError,OSError):
        print('Queue operation failed; verify evidence IDs, scope, labels and selected read operations.')
        return 2

if __name__=='__main__': raise SystemExit(main())
