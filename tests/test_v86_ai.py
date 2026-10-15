"""Offline regression checks for AI integrity, bounded publication and comparison planning."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon81.core import normalize_record, digest
from recon81.context import attach_context
from recon81.reports import generate
from recon81.ai_review import load_json, RESULT_LIMIT, _json, render_review, build_packet
from recon81.review_evidence import split_body
from recon81 import review_batch as batch
from recon81.review_reporting import batch_report, _read_report


def record(path='/orders/10', actor='owner', status=200, text='{"public":true}', scenario=None):
    value=normalize_record('https://example.test'+path,'GET',body=b'',response={
        'status':status,'headers':{'Content-Type':'application/json'},'body':text},source='offline_v86_test')
    return attach_context(value,{'actor':actor,'scenario':scenario or actor,'expected_access':'allow' if actor=='owner' else 'deny'})


def answer(packet):
    reviews=[]
    for item in packet['evidence']:
        if item['fragment'].get('support_only'):continue
        body=item['response']['body']
        if body['kind']=='json_fragment':
            pointer,value=next(iter(body['values'].items()))
            location='response.body.json'
            excerpt=value if isinstance(value,str) else json.dumps(value,separators=(',',':'))
        elif body['kind']=='json':
            pointer='/public';location='response.body.json';excerpt='true'
        else:pointer='';location='response.body.text';excerpt=body['text'][:20]
        reviews.append({'observation_ids':[item['observation_id']],'assessment':'likely_benign','confidence':'low',
                        'reason':'Offline fixture.','evidence_notes':['Saved response only.'],'next_checks':[],
                        'citations':[{'observation_id':item['observation_id'],'location':location,'pointer':pointer,'excerpt':excerpt}],
                        'report_draft':{'title':'Fixture','impact':'Unverified','steps':[],'expected':'Declared policy',
                                        'actual':'Saved response','remediation':'Human review'}})
    return {'packet_id':packet['packet_id'],'summary':'Offline fixture, no model invocation.','reviews':reviews}


class AIIntegrityV86Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.source=self.root/'source';generate([record()],self.source)
    def tearDown(self):self.tmp.cleanup()
    def prepare(self,name='batch',**kwargs):
        directory=self.root/name;batch.prepare_batch(self.source,directory,['example.test'],**kwargs)
        packets=[batch.packet_at(directory,p['packet_id']) for p in batch.verify_batch(directory)['packets']]
        return directory,packets
    def write_answer(self,packet,value=None):
        path=self.root/'answer.json';path.write_text(json.dumps(value or answer(packet),separators=(',',':')))
        return path
    def test_empty_falsey_and_malformed_manifests_never_claim_verification(self):
        path=self.source/'manifest.json'
        for manifest in ({},[],False,0,None,{'files':{}},{'files':[]}):
            path.write_text(json.dumps(manifest))
            with self.subTest(manifest=manifest),self.assertRaises(ValueError):self.prepare()
            self.assertFalse((self.root/'batch').exists())
    def test_verified_receipts_do_not_require_run_id(self):
        path=self.source/'manifest.json';manifest=load_json(path);manifest.pop('run_id',None);path.write_text(json.dumps(manifest))
        _,packets=self.prepare();self.assertTrue(packets[0]['source_manifest_verified'])
    def test_manifest_run_label_is_redacted_in_legacy_and_batch_packets(self):
        path=self.source/'manifest.json';manifest=load_json(path)
        manifest['run_id']='session=SYNTHETIC_PRIVATE_VALUE';path.write_text(json.dumps(manifest))
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',json.dumps(build_packet(self.source,['example.test'])))
        directory,_=self.prepare()
        for path in directory.rglob('*'):
            if path.is_file():self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',path.read_text())
    def test_legacy_metadata_is_redacted_in_every_generated_artifact(self):
        value=record();value['url']+='?api_key=SYNTHETIC_PRIVATE_VALUE'
        value['context']['scenario']='session=SYNTHETIC_PRIVATE_VALUE'
        for body in (value['body'],value['response']['body']):
            body['reason']='session=SYNTHETIC_PRIVATE_VALUE'
            body['fields']=['token=SYNTHETIC_PRIVATE_VALUE']
        (self.source/'requests.jsonl').write_text(json.dumps(value)+'\n');(self.source/'manifest.json').unlink()
        directory,_=self.prepare()
        for path in directory.rglob('*'):
            if path.is_file():self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',path.read_text(),str(path))
    def test_compact_near_limit_result_remains_readable_after_publication(self):
        directory,packets=self.prepare();packet=packets[0];value=answer(packet)
        value['reviews']=[copy.deepcopy(value['reviews'][0]) for _ in range(100)]
        for row in value['reviews']:row['evidence_notes']=['x'*315]*30
        path=self.write_answer(packet,value)
        self.assertLess(path.stat().st_size,RESULT_LIMIT);self.assertGreater(len(_json(value).encode()),RESULT_LIMIT)
        batch.import_packet(directory,packet['packet_id'],path)
        saved=directory/'results'/packet['packet_id']/'ai_review.json'
        self.assertLessEqual(saved.stat().st_size,RESULT_LIMIT)
        self.assertEqual(1,batch.refresh(directory)['summary']['completed_packets'])
    def test_aggregate_budget_rejects_before_committing_result_and_can_retry(self):
        directory,packets=self.prepare();packet=packets[0];path=self.write_answer(packet)
        with patch.object(batch,'AGGREGATE_LIMIT',512),self.assertRaisesRegex(ValueError,'size limit'):
            batch.import_packet(directory,packet['packet_id'],path)
        self.assertFalse((directory/'results'/packet['packet_id']).exists())
        batch.import_packet(directory,packet['packet_id'],path)
        self.assertEqual(1,batch.refresh(directory)['summary']['completed_packets'])
    def test_directory_publish_failure_leaves_no_partial_result(self):
        directory,packets=self.prepare();packet=packets[0];target=directory/'results'/packet['packet_id']
        real_replace=os.replace
        def replace(src,dst):
            if Path(src).is_dir() and Path(dst)==target:raise OSError('synthetic interrupted directory commit')
            return real_replace(src,dst)
        with patch('recon81.ai_review.os.replace',side_effect=replace),self.assertRaises(OSError):
            batch.import_packet(directory,packet['packet_id'],self.write_answer(packet))
        self.assertFalse(target.exists())
        batch.import_packet(directory,packet['packet_id'],self.write_answer(packet))
        self.assertEqual(1,batch.refresh(directory)['summary']['completed_packets'])
    def test_empty_crash_reservation_is_recoverable(self):
        directory,packets=self.prepare();packet=packets[0]
        (directory/'results'/packet['packet_id']).mkdir(parents=True)
        batch.import_packet(directory,packet['packet_id'],self.write_answer(packet))
        self.assertEqual(1,batch.refresh(directory)['summary']['completed_packets'])
    def test_coverage_obeys_writer_lock(self):
        from recon81.locking import advisory_file_lock
        directory,_=self.prepare();before=(directory/'coverage.json').read_bytes()
        lock=directory/'.review-write.lock'
        with advisory_file_lock(lock),self.assertRaises(ValueError):batch.refresh(directory)
        self.assertEqual(before,(directory/'coverage.json').read_bytes());self.assertTrue(lock.exists())
    def test_run_verifies_prepared_batch_once_and_still_detects_tampering(self):
        generate([record('/a'),record('/b')],self.source);directory,packets=self.prepare()
        with patch.object(batch,'_prepared',wraps=batch._prepared) as verify,patch('recon81.codex_review.execute_packet',side_effect=lambda p,*a:(answer(p),{'provider':'fixture'})):
            coverage=batch.run_batch(directory)
        self.assertEqual(1,verify.call_count);self.assertEqual(2,coverage['summary']['completed_packets'])
        result=directory/'results'/packets[0]['packet_id']/'ai_review.json';result.write_text(result.read_text()+' ')
        with self.assertRaises(ValueError):batch.refresh(directory)
    def test_tampering_during_execution_is_detected_before_result_commit(self):
        generate([record('/a'),record('/b')],self.source);directory,packets=self.prepare()
        prompt=directory/'packets'/packets[-1]['packet_id']/'prompt.txt'
        def execute(packet,*args):
            prompt.write_text(prompt.read_text()+' changed')
            return answer(packet),{'provider':'fixture'}
        with patch('recon81.codex_review.execute_packet',side_effect=execute),self.assertRaises(ValueError):batch.run_batch(directory)
        self.assertFalse((directory/'results').exists())
    def test_fragment_hash_is_computed_once_and_expansion_cap_is_early(self):
        text='x'*(512*1024)
        with patch('recon81.review_evidence.digest',wraps=digest) as hashed:
            fragments=split_body({'kind':'text','text':text,'complete':True},1024)
        self.assertEqual(512,len(fragments));self.assertEqual(1,hashed.call_count)
        with self.assertRaisesRegex(ValueError,'fragment budget'):
            split_body({'kind':'text','text':text,'complete':True},1024,max_fragments=5)
    def test_batch_budget_stops_before_expanding_every_source_record(self):
        generate([record('/'+str(i)) for i in range(20)],self.source)
        with patch.object(batch,'MAX_PACKETS',2),patch.object(batch,'expand_record',wraps=batch.expand_record) as expand:
            with self.assertRaisesRegex(ValueError,'Batch limit'):self.prepare()
        self.assertLess(expand.call_count,20);self.assertFalse((self.root/'batch').exists())
    def test_same_resource_controls_stay_together_despite_scenario_labels(self):
        controls=[record(actor='owner'),record(actor='other'),record(actor='admin'),record(actor='denial',status=403)]
        generate(controls,self.source);directory,packets=self.prepare()
        self.assertEqual(1,len(packets));packet=packets[0]
        self.assertEqual({'owner','other','admin','denial'},{r['context']['actor'] for r in packet['evidence']})
        self.assertEqual('complete_saved_group',packet['comparison_context']['coverage'])
        self.assertEqual('matching_saved_selectors',packet['comparison_context']['resource_equivalence'])
    def test_split_comparisons_are_explicitly_partial(self):
        generate([record(actor=actor) for actor in ('owner','other','admin','denial')],self.source)
        directory,packets=self.prepare(max_records=2)
        self.assertEqual(2,len(packets))
        for packet in packets:
            self.assertEqual('partial_saved_group',packet['comparison_context']['coverage'])
            self.assertEqual(2,packet['comparison_context']['missing_observations'])
        self.assertEqual({'partial_saved_group':2},batch.refresh(directory)['summary']['comparison_packets'])
    def test_long_response_rounds_keep_actor_fragments_together(self):
        text=json.dumps({'rows':[{'value':'x'*400} for _ in range(12)]})
        generate([record(actor='owner',text=text),record(actor='other',text=text)],self.source)
        _,packets=self.prepare(body_bytes=1024,max_bytes=16384)
        self.assertGreater(len(packets),1)
        for packet in packets:
            self.assertEqual({'owner','other'},{r['context']['actor'] for r in packet['evidence']})
            self.assertEqual('partial_saved_group',packet['comparison_context']['coverage'])
    def test_masked_selectors_remain_unverified_in_comparison_metadata(self):
        generate([record('/a?token=secret',actor=actor) for actor in ('owner','other')],self.source)
        _,packets=self.prepare()
        self.assertEqual('unverified',packets[0]['comparison_context']['resource_equivalence'])
        self.assertIn('redacted_url_selector',packets[0]['comparison_context']['uncertainty_reasons'])
    def test_comparison_uncertainty_includes_every_record_not_only_last(self):
        incomplete=record(actor='owner');incomplete['body']['complete']=False
        complete=record(actor='other')
        for records in ([incomplete,complete],[complete,incomplete]):
            generate(records,self.source)
            _,packets=self.prepare(name='order-'+records[0]['context']['actor'])
            self.assertEqual(1,len(packets))
            context=packets[0]['comparison_context']
            self.assertEqual('unverified',context['resource_equivalence'])
            self.assertIn('incomplete_request_body',context['uncertainty_reasons'])
    def test_snapshot_report_remains_readable_with_new_comparison_metadata(self):
        directory,packets=self.prepare();packet=packets[0]
        batch.import_packet(directory,packet['packet_id'],self.write_answer(packet))
        output=self.root/'snapshot';batch_report(directory,output)
        reviews,coverage,_=_read_report(output)
        self.assertEqual(1,len(reviews));self.assertIn('comparison_packets',coverage['summary'])


if __name__=='__main__':unittest.main()
