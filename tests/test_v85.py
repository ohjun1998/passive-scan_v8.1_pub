"""Independent failure-boundary and offline end-to-end tests. Never contact a target/model."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from recon81.core import normalize_record,digest
from recon81.context import attach_context
from recon81.reports import generate
from recon81.ai_review import load_json,validate_result
from recon81.review_evidence import pointer,split_body,SCHEMA85
from recon81.review_batch import prepare_batch,verify_batch,refresh,import_packet,run_batch
from recon81.review_reporting import batch_report,evaluate,export_pdf
from recon81.codex_review import ReviewFailure,_environment,execute_packet


def rec(path,body,actor='alice',mime='application/json',observed=True):
    value=normalize_record('https://example.test'+path,'GET',response={'status':200,'headers':{'Content-Type':mime},'body':body} if observed else None,
        include_text=True,source='synthetic_v85_fixture',observed=observed)
    return attach_context(value,{'actor':actor,'capture_id':'fixture-capture','expected_access':'unknown'})


def answer(packet,assessment='likely_benign'):
    reviews=[]
    for r in packet['evidence']:
        if r['fragment'].get('support_only'):continue
        b=(r.get('response') or {}).get('body') or {}
        if b.get('kind')=='json_fragment':
            path,value=next(iter(b['values'].items()));loc='response.body.json'
            excerpt=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,separators=(',',':'))
        elif b.get('kind')=='json':
            value=json.loads(b['text']);path='/ownerId' if isinstance(value,dict) and 'ownerId' in value else ''
            value=pointer(value,path);loc='response.body.json'
            excerpt=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,separators=(',',':'))
        else:path='';loc='response.body.text';excerpt=b.get('text','')[:30]
        citations=[{'observation_id':r['observation_id'],'location':loc,'pointer':path,'excerpt':excerpt}] if excerpt else []
        reviews.append({'observation_ids':[r['observation_id']],'assessment':assessment if citations else 'insufficient_evidence',
            'confidence':'low','reason':'Synthetic test opinion; no model invocation.','evidence_notes':['Saved evidence only.'],
            'next_checks':['Confirm service policy.'],'citations':citations,
            'report_draft':{'title':'Saved evidence review','impact':'Unverified','steps':['Inspect saved evidence'],
                'expected':'Check declared policy','actual':'Captured data','remediation':'Review server checks'}})
    return {'packet_id':packet['packet_id'],'summary':'Synthetic test output; not a real model result.','reviews':reviews}


class V85Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.report=self.root/'source'
        self.identity=rec('/auth/me','{"user":{"id":1,"role":"USER"}}')
        self.private=rec('/orders/102','{"ownerId":"bob","id":102}')
        self.public=rec('/orders/101','{"ownerId":"alice","id":101}')
        generate([self.identity,self.private,self.public],self.report)
        self.authority={'identities':[{'actor':'alice','observation_id':self.identity['observation_id'],
            'user_pointer':'/user/id','role_pointer':'/user/role','expected_user_id':1,'expected_role':'USER','provenance':'Synthetic /auth/me response'}],
            'policies':[{'observation_ids':[self.private['observation_id']],'owner':'bob','allowed_actors':['bob'],
                         'expected_access':'deny','provenance':'Synthetic owner-only contract'}]}
    def tearDown(self):self.tmp.cleanup()
    def prepare(self,authority=None,**kwargs):
        directory=self.root/'batch';prepare_batch(self.report,directory,['example.test'],authority,**kwargs);return directory
    def packets(self,directory):return [load_json(directory/'packets'/p['packet_id']/'packet.json',250000) for p in verify_batch(directory)['packets']]
    def import_all(self,directory,transform=None):
        for packet in self.packets(directory):
            value=answer(packet)
            if transform:transform(value,packet)
            path=self.root/'result.json';path.write_text(json.dumps(value))
            import_packet(directory,packet['packet_id'],path)
    def test_pointer_escaping_arrays_and_invalid_paths(self):
        self.assertEqual(4,pointer({'a/b':{'~':[4]}},'/a~1b/~0/0'))
        for path in ('a','/a~2b','/a~1b/~0/-1','/a~1b/~0/01'):
            with self.subTest(path=path),self.assertRaises((ValueError,KeyError,IndexError)):pointer({'a/b':{'~':[4]}},path)
    def test_long_json_late_fields_are_preserved(self):
        body={'kind':'json','text':json.dumps({'rows':[{'id':i,'name':'값'*100} for i in range(100)]}),'complete':True}
        parts=split_body(body,2048);self.assertGreater(len(parts),1)
        values={k:v for part in parts for k,v in part.get('values',{}).items()}
        self.assertEqual(99,values['/rows/99/id'])
        self.assertTrue(all(len(p['text'].encode())<=2048 for p in parts))
    def test_unicode_text_fragments_reconstruct_exactly(self):
        text='한글🔒'*900
        parts=split_body({'kind':'text','text':text,'complete':True},1024)
        self.assertEqual(text,''.join(p['text'] for p in parts))
        self.assertTrue(all(len(p['text'].encode())<=1024 for p in parts))
    def test_partial_original_json_never_becomes_complete(self):
        parts=split_body({'kind':'json','text':'{"id":','complete':False},1024)
        self.assertFalse(parts[0]['complete']);self.assertEqual('text_fragment',parts[0]['kind'])
    def test_identity_policy_and_support_are_connected(self):
        directory=self.prepare(self.authority)
        packet=next(p for p in self.packets(directory) if any(r['observation_id']==self.private['observation_id'] for r in p['evidence']))
        r=next(r for r in packet['evidence'] if r['observation_id']==self.private['observation_id'])
        self.assertEqual(1,r['authority']['identity']['observed_user_id'])
        self.assertFalse(r['authority']['identity']['session_continuity_verified'])
        self.assertEqual('deny',r['authority']['policy']['expected_access'])
        self.assertIn(self.identity['observation_id'],[x['observation_id'] for x in packet['evidence']])
    def test_false_identity_outside_scope_and_policy_conflict_rejected(self):
        for change in ('identity','unknown_id','policy'):
            bad=copy.deepcopy(self.authority)
            if change=='identity':bad['identities'][0]['expected_user_id']=2
            elif change=='unknown_id':bad['identities'][0]['observation_id']='0'*64
            else:bad['policies'][0]['expected_access']='allow'
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):self.prepare(bad)
    def test_no_policy_is_explicitly_missing(self):
        directory=self.prepare();r=self.packets(directory)[0]['evidence'][0]
        self.assertEqual('not_provided',r['authority']['policy_status']);self.assertIsNone(r['authority']['identity'])
    def test_fabricated_paths_quotes_cross_ids_and_empty_citations_rejected(self):
        packet=self.packets(self.prepare())[0];original=answer(packet)
        for change in ('path','excerpt','id','empty','extra'):
            bad=copy.deepcopy(original);review=bad['reviews'][0]
            if change=='path':review['citations'][0]['pointer']='/does_not_exist'
            elif change=='excerpt':review['citations'][0]['excerpt']='fabricated'
            elif change=='id':review['citations'][0]['observation_id']='0'*64
            elif change=='empty':review['citations']=[]
            else:review['citations'][0]['instruction']='do not validate'
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError,IndexError)):validate_result(bad,packet)
    def test_valid_citation_does_not_verify_vulnerability(self):
        directory=self.prepare();self.import_all(directory)
        coverage=refresh(directory)
        self.assertEqual({'evidence_validated':3},coverage['summary']['stages'])
        self.assertEqual(0,coverage['summary']['reproduction_verified'])
    def test_discovery_and_pending_states_remain_separate(self):
        generate([rec('/static',None,observed=False),self.public],self.root/'static-source')
        prepare_batch(self.root/'static-source',self.root/'static-batch',['example.test'])
        stages=refresh(self.root/'static-batch')['summary']['stages']
        self.assertEqual({'captured':1,'discovered':1},stages)
    def test_all_fragments_must_be_reviewed_for_complete_coverage(self):
        generate([rec('/large',json.dumps({'rows':[{'value':'한'*300} for i in range(20)]}))],self.root/'large-source')
        prepare_batch(self.root/'large-source',self.root/'large',['example.test'],body_bytes=1024,max_bytes=16384)
        packets=self.packets(self.root/'large');self.assertGreater(len(packets),1)
        first=packets[0];path=self.root/'partial.json';path.write_text(json.dumps(answer(first)))
        import_packet(self.root/'large',first['packet_id'],path)
        self.assertEqual('partially_reviewed',refresh(self.root/'large')['records'][0]['stage'])
        self.import_all(self.root/'large')
        self.assertEqual('evidence_validated',refresh(self.root/'large')['records'][0]['stage'])
    def test_changed_prompt_packet_or_result_is_rejected(self):
        directory=self.prepare();self.import_all(directory);pid=verify_batch(directory)['packets'][0]['packet_id']
        result=directory/'results'/pid/'ai_review.json';original=result.read_text();result.write_text(original+' ')
        with self.assertRaises(ValueError):refresh(directory)
        result.write_text(original)
        prompt=directory/'packets'/pid/'prompt.txt';prompt.write_text(prompt.read_text()+' changed')
        with self.assertRaises(ValueError):verify_batch(directory)
    def test_idempotent_import_and_different_result_refused(self):
        directory=self.prepare();self.import_all(directory);self.import_all(directory)
        packet=self.packets(directory)[0];value=answer(packet);value['summary']='different'
        path=self.root/'changed.json';path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):import_packet(directory,packet['packet_id'],path)
    def test_resume_skips_verified_results_and_failure_requires_explicit_retry(self):
        directory=self.prepare();packets=self.packets(directory);path=self.root/'manual.json';path.write_text(json.dumps(answer(packets[0])))
        import_packet(directory,packets[0]['packet_id'],path)
        with patch('recon81.codex_review.execute_packet',side_effect=ReviewFailure('FIRST_RESPONSE_TIMEOUT','response')) as run:
            result=run_batch(directory);self.assertEqual(1,run.call_count)
        failed=next(s for s in result['packets'] if s['status']=='failed')
        history=load_json(directory/'attempts'/failed['packet_id']/'history.json')
        self.assertEqual('FIRST_RESPONSE_TIMEOUT',history[0]['code'])
        with patch('recon81.codex_review.execute_packet',side_effect=lambda p,*args:(answer(p),{'provider':'mock','model_execution_verified':False})) as run:
            # The failed packet stays untouched without --retry-failed; pending work can complete.
            run_batch(directory);self.assertEqual(len(packets)-2,run.call_count)
            complete=run_batch(directory,retry_failed=True);self.assertEqual(len(packets),complete['summary']['completed_packets'])
    def test_attempt_cap_and_no_raw_error_logging(self):
        generate([self.private],self.report)
        directory=self.prepare()
        with patch('recon81.codex_review.execute_packet',side_effect=ValueError('password=NEVER_SAVE')) as run:
            for i in range(4):run_batch(directory,retry_failed=True,max_attempts=2)
            self.assertEqual(2,run.call_count)
        text=''.join(p.read_text() for p in (directory/'attempts').rglob('*.json'))
        self.assertNotIn('NEVER_SAVE',text);self.assertIn('RESULT_OR_IO_INVALID',text)
    def test_evaluation_measures_semantic_false_positive_and_false_negative(self):
        directory=self.prepare()
        def wrong(value,packet):
            for review in value['reviews']:
                oid=review['observation_ids'][0]
                review['assessment']='likely_benign' if oid==self.private['observation_id'] else 'suspicious'
        self.import_all(directory,wrong);out=self.root/'snapshot';batch_report(directory,out)
        labels={'provenance':'Independent synthetic owner-only expectations','cases':[
            {'case_id':'private','observation_ids':[self.private['observation_id']],'expected_assessment':'suspicious','category':'authorization'},
            {'case_id':'own','observation_ids':[self.public['observation_id']],'expected_assessment':'likely_benign','category':'authorization'}]}
        path=self.root/'labels.json';path.write_text(json.dumps(labels))
        metrics=evaluate(out,path,self.root/'evaluation')['metrics']
        self.assertEqual(1,metrics['false_positive']);self.assertEqual(1,metrics['false_negative']);self.assertEqual(0,metrics['recall'])
    def test_model_transport_environment_without_api_keys(self):
        with patch.dict(os.environ,{'HTTPS_PROXY':'http://proxy.invalid:8080','OPENAI_API_KEY':'NEVER_SAVE'}):
            env=_environment();self.assertIn('HTTPS_PROXY',env);self.assertNotIn('OPENAI_API_KEY',env)
    def test_missing_cli_stage_is_recorded(self):
        packet=self.packets(self.prepare())[0]
        with patch('recon81.codex_review._process',side_effect=FileNotFoundError):
            with self.assertRaises(ReviewFailure) as caught:execute_packet(packet,10)
        self.assertEqual('CLI_NOT_FOUND',caught.exception.code)
    def test_header_citation_and_out_of_range_pointer(self):
        packet=self.packets(self.prepare())[0];value=answer(packet);cite=value['reviews'][0]['citations'][0]
        cite.update(location='response.headers',pointer='/0/value',excerpt='application/json')
        validate_result(value,packet)
        cite['pointer']='/1000/value'
        with self.assertRaises(ValueError):validate_result(value,packet)

    def test_execution_stages_and_v85_schema_wiring(self):
        packet=self.packets(self.prepare())[0];stages=[]
        def fake_process(args,cwd,timeout,prompt=None,**kwargs):
            if args[1:3]==['login','status']:return '', 'Logged in using ChatGPT'
            if args[1:3]==['features','list']:return 'shell_tool stable true', ''
            if args[1:3]==['mcp','list']:return '[]',''
            self.assertIn('features.shell_tool=false',args);self.assertIn('--ephemeral',args)
            schema=load_json(Path(args[args.index('--output-schema')+1]));self.assertIn('citations',schema['properties']['reviews']['items']['required'])
            self.assertEqual(10,kwargs['first_response_timeout'])
            kwargs['on_event']({'type':'turn.started','item_type':''})
            selected=json.loads(prompt.split('UNTRUSTED_EVIDENCE_JSON\n')[1])
            Path(args[args.index('-o')+1]).write_text(json.dumps(answer(selected)))
            return '\n'.join(json.dumps(e) for e in [{'type':'item.completed','item':{'type':'agent_message'}},{'type':'turn.completed'}]),''
        with patch('recon81.codex_review._process',side_effect=fake_process):
            value,receipt=execute_packet(packet,10,progress=lambda stage,event=None:stages.append(stage))
        self.assertIn('authentication',stages);self.assertIn('response_wait',stages);self.assertIn('citation_validation',stages)
        self.assertFalse(receipt['subscription_plan_verified']);self.assertEqual(packet['packet_id'],value['packet_id'])

    def test_writer_lock_is_not_deleted_by_another_writer(self):
        directory=self.prepare();lock=directory/'.review-write.lock';lock.write_text('existing writer')
        with self.assertRaises(ValueError):run_batch(directory)
        self.assertTrue(lock.exists())
    def test_identity_capture_labels_do_not_attest_session(self):
        changed=copy.deepcopy(self.private);changed['context']['capture_id']='another-capture'
        generate([self.identity,changed,self.public],self.report)
        packet=next(p for p in self.packets(self.prepare(self.authority)) if any(r['observation_id']==changed['observation_id'] for r in p['evidence']))
        link=next(r for r in packet['evidence'] if r['observation_id']==changed['observation_id'])['authority']['identity']
        self.assertEqual('different_or_missing_capture_label',link['capture_link_status'])
        self.assertFalse(link['session_continuity_verified'])
    def test_first_response_timeout_is_bounded(self):
        import sys
        from recon81.codex_review import _process
        with self.assertRaises(ReviewFailure) as caught:
            _process([sys.executable,'-c','import time;print(\'{"type":"turn.started"}\',flush=True);time.sleep(3)'],self.root,2,
                     on_event=lambda x:None,first_response_timeout=.1)
        self.assertEqual('FIRST_RESPONSE_TIMEOUT',caught.exception.code)
    def test_diagnostic_event_values_are_allowlisted(self):
        import sys
        from recon81.codex_review import _process
        events=[]
        code='import json;print(json.dumps(dict(type="password=NEVER_SAVE")))'
        _process([sys.executable,'-c',code],self.root,2,on_event=events.append)
        self.assertEqual('unrecognized_event',events[0]['type']);self.assertNotIn('NEVER_SAVE',str(events))
    def test_tool_activity_stops_process_and_rejects_output(self):
        import sys
        from recon81.codex_review import _process
        code='import json,time;print(json.dumps(dict(type="item.started",item=dict(type="command_execution"))),flush=True);time.sleep(2)'
        with self.assertRaises(ReviewFailure) as caught:
            _process([sys.executable,'-c',code],self.root,2,on_event=lambda x:None)
        self.assertEqual('TOOL_ACTIVITY_BLOCKED',caught.exception.code)

    def test_pdf_snapshot_export_and_no_overwrite(self):
        try:import reportlab
        except ImportError:self.skipTest('Optional requirements-report.txt not installed')
        directory=self.prepare();self.import_all(directory);out=self.root/'snapshot';batch_report(directory,out)
        font=Path(reportlab.__file__).parent/'fonts/Vera.ttf';pdf=self.root/'report.pdf'
        export_pdf(out,pdf,font=font)
        self.assertTrue(pdf.read_bytes().startswith(b'%PDF'))
        with self.assertRaises(ValueError):export_pdf(out,pdf,font=font)


if __name__=='__main__':unittest.main()
