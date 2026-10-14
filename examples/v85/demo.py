#!/usr/bin/env python3
"""Offline synthetic demonstration. Preset opinions are fixtures, not real AI quality results."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from recon81.core import normalize_record
from recon81.context import attach_context
from recon81.reports import generate
from recon81.review_batch import prepare_batch,import_packet,verify_batch
from recon81.review_reporting import batch_report,evaluate
from recon81.ai_review import load_json
from recon81.review_evidence import pointer


def make(path,body):
    return attach_context(normalize_record('https://example.test'+path,'GET',response={
        'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps(body)},source='synthetic_v85_demo'),
        {'actor':'alice','capture_id':'demo','expected_access':'unknown'})


def run(output):
    output=Path(output)
    if output.exists():raise ValueError('Use a new demo output directory')
    identity=make('/auth/me',{'user':{'id':1,'role':'USER'}})
    private=make('/orders/102',{'ownerId':'bob','id':102});own=make('/orders/101',{'ownerId':'alice','id':101})
    records=[identity,private,own];generate(records,output/'base')
    authority={'identities':[{'actor':'alice','observation_id':identity['observation_id'],'user_pointer':'/user/id',
        'role_pointer':'/user/role','expected_user_id':1,'expected_role':'USER','provenance':'Synthetic identity response'}],
        'policies':[{'observation_ids':[private['observation_id']],'owner':'bob','allowed_actors':['bob'],
                    'expected_access':'deny','provenance':'Synthetic owner-only contract'}]}
    (output/'authority.json').write_text(json.dumps(authority,indent=2))
    prepare_batch(output/'base',output/'batch',['example.test'],authority)
    for spec in verify_batch(output/'batch')['packets']:
        packet=load_json(output/'batch/packets'/spec['packet_id']/'packet.json');reviews=[]
        for r in packet['evidence']:
            if r['fragment'].get('support_only'):continue
            path='/ownerId' if r['observation_id']!=identity['observation_id'] else '/user/id'
            value=pointer(json.loads(r['response']['body']['text']),path)
            excerpt=value if isinstance(value,str) else str(value)
            reviews.append({'observation_ids':[r['observation_id']],'assessment':'suspicious' if r['observation_id']==private['observation_id'] else 'likely_benign',
                'confidence':'low','reason':'Preset synthetic example. No model invoked.','evidence_notes':['Saved response only.'],
                'next_checks':['Confirm declared policy.'],'citations':[{'observation_id':r['observation_id'],
                'location':'response.body.json','pointer':path,'excerpt':excerpt}],
                'report_draft':{'title':'Synthetic evidence demonstration','impact':'Unverified synthetic impact','steps':['Read saved response'],
                    'expected':'Declared owner-only access','actual':'Saved response','remediation':'Check object authorization'}})
        result={'packet_id':packet['packet_id'],'summary':'Fixture result, not an AI detection-quality result.','reviews':reviews}
        path=output/('fixture-'+packet['packet_id']+'.json');path.write_text(json.dumps(result))
        import_packet(output/'batch',packet['packet_id'],path)
    batch_report(output/'batch',output/'report')
    labels={'provenance':'Independent synthetic owner-only labels; answers are preset fixtures','cases':[
        {'case_id':'private','observation_ids':[private['observation_id']],'expected_assessment':'suspicious','category':'authorization'},
        {'case_id':'own','observation_ids':[own['observation_id']],'expected_assessment':'likely_benign','category':'authorization'}]}
    path=output/'labels.json';path.write_text(json.dumps(labels,indent=2))
    result=evaluate(output/'report',path,output/'evaluation')
    print(json.dumps({'fixture_only':True,'network_requests_sent':0,'evaluation':result['metrics']}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);run(p.parse_args().output)
