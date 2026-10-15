import hashlib
import json
import tempfile
import time
import unittest
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from recon81.core import Inventory,normalize_record,normalize_body,MASK
from recon81.context import attach_context
from recon81.analysis import analyze,comparisons,response_diff,flows
from recon81.importers import native_record,load_records,js_record
from recon81.discovery import openapi_records,form_records
from recon81.graphql_policy import read_only_graphql
from recon81.network_policy import NetworkPolicy,PolicyDenied
from recon81.guard import RunGuard,ProtectedHTTP
from recon81.assets import entries,update_analysis,reuse_analysis
from recon81.reports import generate,postman
from request_inventory import main
from download_js import download
from review_queue import build,execute,executable


class V82Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.policy=NetworkPolicy(['example.test'])
    def tearDown(self): self.temp.cleanup()
    def record(self,actor='user-a',url='https://example.test/api/orders/123',method='GET',body=b'',response='{"id":123,"ownerId":"user-a"}',**context):
        r=normalize_record(url,method,{'Content-Type':'application/json','Authorization':'Bearer PRIVATE_TEST_VALUE'},body,{'status':200,'headers':{'Content-Type':'application/json'},'body':response},source='har')
        return attach_context(r,dict(actor=actor,**context))

    def test_actor_labels_prevent_masked_credentials_from_merging_observations(self):
        a=self.record();b=self.record(actor='user-b')
        self.assertEqual(a['request_id'],b['request_id'])
        self.assertNotEqual(a['observation_id'],b['observation_id'])
        self.assertNotIn('PRIVATE_TEST_VALUE',json.dumps(a))
        with Inventory(self.root/'old.db') as inv: inv.add(a);inv.add(b)
        with Inventory(self.root/'old.db') as inv: self.assertEqual(2,len(list(inv.records())))
        self.assertEqual(a['observation_id'],native_record(a)['observation_id'])

    def test_old_observation_ids_remain_compatible(self):
        r=normalize_record('https://example.test/api','GET',body=b'')
        oid=r['observation_id'];attach_context(r,{})
        self.assertEqual(oid,r['observation_id'])
        self.assertEqual(oid,native_record(r)['observation_id'])

    def test_import_labels_and_transactional_review_updates(self):
        path=self.root/'urls.txt';path.write_text('https://example.test/api\n')
        db=self.root/'inventory.db'
        self.assertEqual(0,main(['import',str(path),'--scope','example.test','--actor','user-a','--scenario','order-view','--capture-id','flow-1','--expected-access','deny','--db',str(db)]))
        with Inventory(db) as inv:
            r=list(inv.records())[0];self.assertEqual('user-a',r['context']['actor'])
            with self.assertRaises(ValueError): inv.review(r['observation_id'],'confirmed','')
            inv.review(r['observation_id'],'deferred','Need actual response')
        edits=self.root/'edits.json';edits.write_text(json.dumps({'reviews':[{'observation_id':r['observation_id'],'state':'confirmed','note':'manual evidence'}, {'observation_id':'unknown','state':'confirmed','note':'bad'}]}))
        self.assertEqual(2,main(['review','--db',str(db),'--file',str(edits)]))
        with Inventory(db) as inv: self.assertEqual('deferred',list(inv.records())[0]['review']['state'])

    def test_priority_uses_actual_evidence_without_auto_verdict(self):
        r=self.record(method='POST',body='{"ownerId":"user-a","role":"user"}',expected_access='deny')
        data,analysis=analyze([r]);self.assertGreaterEqual(data[0]['triage']['score'],60)
        self.assertEqual('captured',data[0]['review']['state'])
        self.assertTrue(data[0]['triage']['not_a_vulnerability_verdict'])
        self.assertEqual(1,analysis['summary']['unreviewed'])

    def test_comparison_matches_exact_resource_and_payload(self):
        a=self.record();b=self.record(actor='user-b',response='{"id":123,"ownerId":"user-b"}');c=self.record(actor='user-c',url='https://example.test/api/orders/124')
        pairs,_=comparisons([a,b,c]);self.assertEqual(1,len(pairs))
        self.assertEqual('$.ownerId',pairs[0]['differences'][0]['field'])

    def test_missing_request_body_cannot_be_assumed_to_match(self):
        a=self.record(method='POST',body=None);b=self.record(actor='user-b',method='POST',body=None)
        self.assertEqual([],comparisons([a,b])[0])

    def test_json_property_order_does_not_hide_actor_comparison(self):
        a=self.record(method='POST',body='{"id":123,"kind":"order"}')
        b=self.record(actor='user-b',method='POST',body='{"kind":"order","id":123}')
        self.assertEqual(1,len(comparisons([a,b])[0]))

    def test_comparison_ignores_only_configured_fields_and_keeps_evidence(self):
        a=self.record(response='{"id":123,"meta":{"trace":"a"}}');b=self.record(actor='user-b',response='{"id":124,"meta":{"trace":"b"}}')
        diff=response_diff(a,b,['$.meta.trace'])
        self.assertEqual(['$.id'],[x['field'] for x in diff['differences']])
        self.assertIn('"trace": "a"',a['response']['body']['text'])

    def test_incomplete_response_is_not_equivalent_or_normal(self):
        a=self.record();b=self.record(actor='user-b',response=None)
        diff=response_diff(a,b);self.assertFalse(diff['comparable'])
        self.assertEqual('incomplete_response_body',diff['reason'])
        _,analysis=analyze([a,b]);self.assertEqual(2,analysis['summary']['unreviewed'])

    def test_static_post_is_not_covered_by_observed_get(self):
        a=self.record();b=js_record({'url':a['url'],'method':'POST','bodyParams':['ownerId']})
        _,analysis=analyze([a,b]);self.assertEqual(2,len(analysis['coverage']))
        self.assertEqual('discovered',next(x for x in analysis['coverage'] if x['method']=='POST')['coverage'])

    def test_flow_links_values_only_within_same_actor_and_capture(self):
        a=self.record(url='https://example.test/api/upload',method='POST',body='{}',response='{"fileId":55}',scenario='file-download',capture_id='flow-1')
        b=self.record(url='https://example.test/files/55',scenario='file-download',capture_id='flow-1')
        c=self.record(actor='user-b',url='https://example.test/files/55',scenario='file-download',capture_id='flow-1')
        a['timestamp']='2026-10-12T01:00:00Z';b['timestamp']='2026-10-12T01:00:01Z';c['timestamp']='2026-10-12T01:00:02Z'
        result=flows([a,b,c]);self.assertEqual(2,len(result))
        self.assertEqual(1,sum(len(x['links']) for x in result))

    def test_openapi_local_refs_preserve_schema_and_do_not_create_body_values(self):
        doc={'openapi':'3.1.0','servers':[{'url':'https://example.test/api'}],'paths':{'/orders/{id}':{'post':{'parameters':[{'name':'id','in':'path','schema':{'type':'integer'}}],'requestBody':{'content':{'application/json':{'schema':{'$ref':'#/components/schemas/Order'}}}},'responses':{}}}},'components':{'schemas':{'Order':{'type':'object','required':['ownerId'],'properties':{'ownerId':{'type':'string'},'password':{'type':'string','example':'NEVER_COPY'}}}}}}
        with patch('urllib.request.urlopen',side_effect=AssertionError('offline only')):
            r=list(openapi_records(json.dumps(doc).encode()))[0]
        self.assertFalse(r['observed']);self.assertIn('$.ownerId',r['body']['fields'])
        self.assertEqual('',r['body']['text']);self.assertNotIn('NEVER_COPY',json.dumps(r))
        self.assertEqual('integer',r['schema']['parameters'][0]['type'])

    def test_external_openapi_refs_are_never_fetched_and_cycles_are_bounded(self):
        doc={'openapi':'3.0.0','paths':{'/api':{'post':{'requestBody':{'$ref':'https://outside.test/schema'},'responses':{}}}}}
        with patch('urllib.request.urlopen',side_effect=AssertionError('No external refs')):
            r=list(openapi_records(json.dumps(doc).encode(),'https://example.test'))[0]
        self.assertEqual([],r['body']['fields'])

    def test_forms_do_not_submit_or_copy_default_secrets(self):
        data=b'<form action="/upload" method="POST" enctype="multipart/form-data"><input type="file" name="file"><input name="token" value="NEVER_COPY"></form>'
        r=list(form_records(data,'https://example.test/page'))[0]
        self.assertEqual(['file','token'],r['body']['fields']);self.assertFalse(r['observed'])
        self.assertNotIn('NEVER_COPY',json.dumps(r))

    def test_graphql_ast_handles_operation_names_fragments_and_literals(self):
        payload={'query':'query A { ...User } query B { other } fragment User on User { name(note:"mutation is a word") }','operationName':'A'}
        self.assertTrue(read_only_graphql(json.dumps(payload).encode()))
        payload.pop('operationName');self.assertFalse(read_only_graphql(json.dumps(payload).encode()))
        self.assertFalse(read_only_graphql(b'{"query":"query { ...A } fragment A on User { ...A }"}'))
        self.assertFalse(read_only_graphql(b'{"query":"query($n:Int=10000){ users(first:$n){id} }"}'))
        aliases=' '.join('a'+str(i)+':user{id}' for i in range(31))
        self.assertFalse(read_only_graphql(json.dumps({'query':'{'+aliases+'}'}).encode()))

    def test_graphql_selected_query_does_not_execute_other_mutation(self):
        payload={'query':'query View{me{id}} mutation Change{deleteUser}','operationName':'View'}
        self.assertTrue(read_only_graphql(json.dumps(payload).encode()))
        payload['operationName']='Change';self.assertFalse(read_only_graphql(json.dumps(payload).encode()))

    def test_queue_build_is_offline_and_never_contains_credentials(self):
        plan=build([self.record()],self.policy)
        self.assertTrue(plan['items'][0]['baseline_eligible'])
        self.assertNotIn('PRIVATE_TEST_VALUE',json.dumps(plan))

    def test_queue_cannot_be_tampered_or_replay_mutation(self):
        r=self.record();client=Mock(guard=SimpleNamespace(max_requests=20))
        with Inventory(self.root/'db') as inv:
            inv.add(r);plan=build(list(inv.records()),self.policy);plan['items'][0]['url']='https://outside.test/'
            with self.assertRaises(ValueError): execute(inv,plan,[r['observation_id']],client,self.policy,'user-b')
        client.fetch.assert_not_called()
        mutation=self.record(method='POST',body='{"query":"mutation { deleteUser }"}',operation='read')
        self.assertFalse(executable(mutation,self.policy,[mutation['url']])[0])

    def test_queue_validates_all_selections_before_first_request(self):
        a=self.record();b=self.record(url='https://example.test/api/delete/1')
        client=Mock(guard=SimpleNamespace(max_requests=20))
        with Inventory(self.root/'db') as inv:
            inv.add(a);inv.add(b);plan=build(list(inv.records()),self.policy)
            with self.assertRaises(ValueError): execute(inv,plan,[a['observation_id'],b['observation_id']],client,self.policy,'user-b')
        client.fetch.assert_not_called()

    def test_queue_collects_baseline_and_masks_runtime_credentials(self):
        a=self.record();client=Mock(guard=SimpleNamespace(max_requests=20))
        client.fetch.return_value={'status':200,'headers':{'Content-Type':'application/json'},'body':b'{"ownerId":"user-b"}','complete':True}
        with Inventory(self.root/'db') as inv:
            inv.add(a);plan=build(list(inv.records()),self.policy)
            result=execute(inv,plan,[a['observation_id']],client,self.policy,'user-b',headers={'Authorization':'Bearer RUNTIME_TEST_SECRET'})
            records=list(inv.records())
        self.assertEqual(1,result['baselines_collected']);self.assertEqual(0,result['automatically_confirmed_vulnerabilities'])
        self.assertNotIn('RUNTIME_TEST_SECRET',json.dumps(records))
        self.assertEqual('Bearer RUNTIME_TEST_SECRET',client.fetch.call_args.args[2]['Authorization'])
        self.assertEqual({'user-a','user-b'},{r['context']['actor'] for r in records})

    def test_generic_read_post_needs_exact_url_and_explicit_operation_label(self):
        r=self.record(url='https://example.test/api/search',method='POST',body='{"query":"cats"}',operation='read')
        self.assertFalse(executable(r,self.policy)[0])
        self.assertTrue(executable(r,self.policy,[r['url']])[0])

    def test_real_read_baseline_loopback_transport_and_no_redirect_follow(self):
        hits=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                hits.append(self.path)
                if self.path=='/api/redirect':
                    self.send_response(302);self.send_header('Location',f'http://localhost:{self.server.server_port}/unexpected');self.end_headers();return
                data=b'{"ownerId":"user-b"}'
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        guard=RunGuard(self.root/'runtime.db',interval=0,max_requests=2)
        policy=NetworkPolicy(['127.0.0.1'],allowed_ports=[server.server_port])
        try:
            with Inventory(self.root/'evidence.db') as inv:
                source=[]
                for path in ('/api/read','/api/redirect'):
                    r=self.record(url=f'http://127.0.0.1:{server.server_port}'+path);source.append(r);inv.add(r)
                plan=build(list(inv.records()),policy)
                result=execute(inv,plan,[r['observation_id'] for r in source],ProtectedHTTP(policy,guard),policy,'user-b',headers={'Authorization':'Bearer LOCAL_FIXTURE_ONLY'})
                stored=list(inv.records())
            self.assertEqual(2,result['baselines_collected']);self.assertEqual(['/api/read','/api/redirect'],hits)
            self.assertNotIn('LOCAL_FIXTURE_ONLY',json.dumps(stored))
            self.assertTrue(any(r['source']=='validation_baseline' and r['response']['status']==302 for r in stored))
        finally:guard.close();server.shutdown();server.server_close();worker.join(timeout=2)

    def test_static_assets_under_report_path_do_not_use_generation_budget(self):
        self.assertFalse(self.policy.is_costly('https://example.test/reports/main.js'))
        self.assertTrue(self.policy.is_costly('https://example.test/reports/export'))

    def test_method_override_is_blocked_before_network(self):
        g=RunGuard(self.root/'guard.db',interval=0);client=ProtectedHTTP(self.policy,g);client.opener=Mock()
        try:
            with self.assertRaises(PolicyDenied): client.fetch('https://example.test/api',headers={'X-HTTP-Method-Override':'DELETE'})
            client.opener.open.assert_not_called();self.assertEqual(0,g.state()['requests'])
        finally:g.close()

    def test_js_content_and_analyzer_cache_reuse_and_delta(self):
        url='https://example.test/main.js';key=hashlib.sha256(url.encode()).hexdigest();cache=self.root/'cache.jsonl';mapping=self.root/'mapping'
        cache.write_text(json.dumps({'url_hash':key,'url':url,'downloaded_at':time.time(),'content_hash':'a'*64})+'\n')
        a=js_record({'url':'https://example.test/api/a','method':'GET'},url)
        first=update_analysis(cache,key,'a'*64,'tool-v1',[a]);mapping.write_text(key+'.js\t'+url+'\n')
        reused=reuse_analysis(cache,mapping,'tool-v1');self.assertTrue(reused[0]['asset']['reused'])
        self.assertEqual([],reuse_analysis(cache,mapping,'tool-v2'))
        current=entries(cache)[key];current['content_hash']='b'*64;current['downloaded_at']+=1;cache.write_text(json.dumps(current)+'\n')
        b=js_record({'url':'https://example.test/api/b','method':'POST','bodyParams':['id']},url)
        updated=update_analysis(cache,key,'b'*64,'tool-v1',[b])[0]
        self.assertEqual('changed',updated['asset']['change_kind']);self.assertEqual(1,updated['asset']['removed_count'])
        self.assertNotEqual(first[0]['observation_id'],updated['observation_id'])

    def test_successful_js_revalidation_304_reuses_without_body_download(self):
        url='https://example.test/main.js';key=hashlib.sha256(url.encode()).hexdigest();cache=self.root/'cache.jsonl';mapping=self.root/'mapping'
        item={'url_hash':key,'url':url,'downloaded_at':time.time(),'content_hash':'a'*64,'etag':'"v1"','analysis':{'content_hash':'a'*64,'analyzer_version':'tool-v1','records':[]}}
        cache.write_text(json.dumps(item)+'\n');client=Mock();client.fetch.return_value={'status':304,'complete':True,'body':b'','headers':{}}
        self.assertEqual(0,download([url],client,self.policy,self.root/'js',mapping,cache,min_free_bytes=0,analyzer_version='tool-v1',revalidate=True))
        self.assertEqual({'If-None-Match':'"v1"'},client.fetch.call_args.kwargs['headers'])
        client.get.assert_not_called();self.assertIn(url,mapping.read_text())

    def test_analyzer_change_requires_source_even_when_download_cache_is_fresh(self):
        url='https://example.test/main.js';key=hashlib.sha256(url.encode()).hexdigest();cache=self.root/'cache.jsonl'
        cache.write_text(json.dumps({'url_hash':key,'url':url,'downloaded_at':time.time(),'content_hash':'a'*64,'analysis':{'content_hash':'a'*64,'analyzer_version':'old','records':[]}})+'\n')
        client=Mock();client.get.return_value={'status':200,'body':b'const a=1','complete':True,'headers':{}}
        self.assertEqual(1,download([url],client,self.policy,self.root/'js',self.root/'mapping',cache,min_free_bytes=0,analyzer_version='new'))
        client.get.assert_called_once()

    def test_report_has_dashboard_and_review_data_with_injection_defense(self):
        a=self.record(actor='=HYPERLINK("https://example.test")',method='POST',body='{"nickname":"</script><script>alert(1)</script>"}')
        output=self.root/'report';generate([a],output,True)
        html=(output/'index.html').read_text();self.assertNotIn('</script><script>alert(1)</script>',html)
        self.assertIn('계정 비교',html);self.assertIn('커버리지',html);self.assertIn("connect-src 'none'",html)
        self.assertTrue((output/'analysis.json').exists());self.assertTrue((output/'review_queue.json').exists())
        from openpyxl import load_workbook
        wb=load_workbook(output/'request_inventory.xlsx');self.assertNotEqual('f',wb['Candidates v8.2']['D2'].data_type)

    def test_postman_keeps_distinct_actor_context_and_stays_execution_blocked(self):
        result=postman([self.record(),self.record(actor='user-b')]);self.assertEqual(2,len(result['item']))
        self.assertIn('throw new Error',result['event'][0]['script']['exec'][0])

    def test_nonfinite_json_is_not_embedded_in_dashboard(self):
        self.assertEqual('omitted',normalize_body(b'{"x":NaN}','application/json')['kind'])

    def test_response_comparison_checks_late_values_empty_containers_and_types(self):
        a=self.record(response=json.dumps({'items':list(range(105)), 'empty':{}}))
        values=list(range(105));values[104]='changed'
        b=self.record(actor='user-b',response=json.dumps({'items':values,'empty':[]}))
        diff=response_diff(a,b)
        self.assertTrue(diff['comparable'])
        self.assertEqual({'$.items[104]','$.empty'},{d['field'] for d in diff['differences']})

    def test_response_comparison_reports_complexity_limit_instead_of_equality(self):
        a=self.record(response=json.dumps(list(range(12001))))
        b=self.record(actor='user-b',response=json.dumps(list(range(12001))))
        diff=response_diff(a,b)
        self.assertFalse(diff['comparable']);self.assertEqual('comparison_complexity_limit',diff['reason'])

    def test_response_comparison_preserves_duplicate_form_fields_and_literal_keys(self):
        a=self.record(response='{"a.b":1,"a":{"b":2}}')
        b=self.record(actor='user-b',response='{"a.b":3,"a":{"b":2}}')
        self.assertEqual('$["a.b"]',response_diff(a,b)['differences'][0]['field'])
        for r,text in ((a,'id=1&id=2'),(b,'id=9&id=2')):
            r['response']['body']=normalize_body(text,'application/x-www-form-urlencoded')
        self.assertTrue(response_diff(a,b)['differences'])

    def test_openapi_coverage_preserves_base_path(self):
        doc={'openapi':'3.1.0','paths':{'/orders/{id}':{'get':{'responses':{}}}}}
        record=list(openapi_records(json.dumps(doc).encode(),'https://example.test/api/v2'))[0]
        _,analysis=analyze([record])
        self.assertEqual('https://example.test/api/v2/orders/{id}',analysis['coverage'][0]['route'])

if __name__=='__main__':unittest.main()
