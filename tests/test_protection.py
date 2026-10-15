import hashlib
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from recon81.core import Scope
from recon81.network_policy import NetworkPolicy, PolicyDenied
from recon81.guard import RunGuard, ProtectedHTTP, GuardStopped, retry_after_seconds
from download_js import download, cached_keys
from crawl_safe import crawl
from guarded_probe import command, supervise
from guarded_crawl import scope_regex
from safe_screenshots import BrowserGate, read_only_graphql, select_pages


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.policy=NetworkPolicy(Scope(['example.test']))
        self.guard=RunGuard(self.root/'guard.db',interval=0)
    def tearDown(self):
        self.guard.close(); self.temp.cleanup()

    def test_policy_blocks_actions_before_network(self):
        for url in ['https://example.test/delete/1','https://example.test/%64elete/1','https://example.test/a?token=x','https://example.test/a?action=send','https://example.test/a?limit=500','https://example.test:443@outside.test/a']:
            self.assertIsNotNone(self.policy.reason(url),url)
        client=ProtectedHTTP(self.policy,self.guard)
        client.opener=Mock()
        with self.assertRaises(PolicyDenied): client.get('https://example.test/delete/1')
        client.opener.open.assert_not_called()

    def test_keep_valuable_costly_endpoints(self):
        self.assertIsNone(self.policy.reason('https://example.test/download?id=1'))
        self.assertIsNone(self.policy.reason('https://example.test/export'))
        self.assertTrue(self.policy.is_costly('https://example.test/export'))
        for _ in range(3): self.guard.reserve('https://example.test/export')
        with self.assertRaises(GuardStopped): self.guard.reserve('https://example.test/export')
        self.guard.reserve('https://example.test/profile')

    def test_policy_preserves_common_alternate_ports(self):
        self.assertIsNone(self.policy.reason('https://example.test:8443/'))
        self.assertEqual('unreviewed_port',self.policy.reason('https://example.test:9999/'))

    def test_manual_reviewed_actions_supported(self):
        p=NetworkPolicy(['example.test'],reviewed_paths=['/profile'],allow_user_actions=True)
        self.assertIsNone(p.reason('https://example.test/profile','PUT',manual=True))
        self.assertIsNotNone(p.reason('https://example.test/profile','PUT'))

    def test_httpx_parameters_preserved(self):
        argv=command('httpx','urls.txt')
        self.assertEqual('10',argv[argv.index('-rl')+1])
        self.assertEqual('5',argv[argv.index('-t')+1])
        self.assertEqual('0',argv[argv.index('-retries')+1])
        self.assertIn('-no-fallback-scheme',argv)
        self.assertNotIn('-no-fallback',argv)

    def test_scope_regex_is_exact_not_prefix_or_userinfo(self):
        import re
        rx=re.compile(scope_regex(self.policy))
        self.assertTrue(rx.search('https://example.test/a'))
        self.assertFalse(rx.search('https://example.test.attacker.test/a'))
        self.assertFalse(rx.search('https://example.test@outside.test/a'))

    def test_overload_stops_new_requests(self):
        with self.assertRaises(GuardStopped): self.guard.feedback(429,retry_after='60')
        self.assertEqual(60,self.guard.state()['retry_after'])
        with self.assertRaises(GuardStopped): self.guard.reserve()
        self.assertEqual(0,self.guard.state()['requests'])

    def test_one_ordinary_failure_does_not_remove_functionality(self):
        self.guard.feedback(500)
        self.guard.reserve()
        self.guard.feedback(200)
        self.assertFalse(self.guard.state()['stopped'])

    def test_repeated_failures_and_sustained_latency_stop(self):
        self.guard.feedback(failed=True); self.guard.feedback(failed=True)
        with self.assertRaises(GuardStopped): self.guard.feedback(failed=True)
        other=RunGuard(self.root/'other.db',interval=0)
        try:
            for _ in range(5): other.feedback(200,elapsed=0.1)
            other.feedback(200,elapsed=3); other.feedback(200,elapsed=3)
            with self.assertRaises(GuardStopped): other.feedback(200,elapsed=3)
        finally: other.close()

    def test_byte_and_request_budgets(self):
        g=RunGuard(self.root/'small.db',max_requests=1,max_bytes=4,interval=0)
        try:
            g.reserve()
            with self.assertRaises(GuardStopped): g.reserve()
            g.consume(4)
            with self.assertRaises(GuardStopped): g.consume(1)
        finally: g.close()

    def test_retry_after_parser(self):
        self.assertEqual(30,retry_after_seconds('30'))
        self.assertEqual(0,retry_after_seconds('bad'))

    def test_http_429_closes_response_and_never_retries(self):
        client=ProtectedHTTP(self.policy,self.guard)
        body=io.BytesIO(b'overload')
        error=HTTPError('https://example.test/',429,'busy',{'Retry-After':'10'},body)
        client.opener=Mock(); client.opener.open.side_effect=error
        with self.assertRaises(GuardStopped): client.get('https://example.test/')
        self.assertTrue(body.closed)
        self.assertEqual(1,client.opener.open.call_count)

    def test_redirect_is_not_automatically_followed(self):
        client=ProtectedHTTP(self.policy,self.guard)
        client.opener=Mock()
        client.opener.open.side_effect=HTTPError('https://example.test/',302,'redirect',{'Location':'https://outside.test/'},io.BytesIO(b''))
        result=client.get('https://example.test/')
        self.assertEqual(302,result['status'])
        self.assertEqual(1,client.opener.open.call_count)

    def test_probe_stop_preserves_overload_evidence(self):
        output=self.root/'out.jsonl'
        fake='import json,time; print(json.dumps({"url":"https://example.test/","status_code":429}),flush=True); time.sleep(10)'
        self.assertEqual(3,supervise([sys.executable,'-c',fake],output,self.guard,self.policy,deadline=5))
        self.assertIn('429',output.read_text())

    def test_successful_probe_returns_normally(self):
        output=self.root/'out.jsonl'
        fake='import json; print(json.dumps({"url":"https://example.test/","status_code":200}))'
        self.assertEqual(0,supervise([sys.executable,'-c',fake],output,self.guard,self.policy,deadline=5))

    def test_partial_tool_line_cannot_bypass_deadline(self):
        fake='import sys,time; sys.stdout.write("{"); sys.stdout.flush(); time.sleep(10)'
        start=time.monotonic()
        self.assertEqual(3,supervise([sys.executable,'-c',fake],self.root/'partial.jsonl',self.guard,self.policy,deadline=0.3))
        self.assertLess(time.monotonic()-start,4)

    def test_tool_without_final_newline_preserves_result(self):
        fake='import json,sys; sys.stdout.write(json.dumps({"url":"https://example.test/","status_code":200}))'
        output=self.root/'no-newline.jsonl'
        self.assertEqual(0,supervise([sys.executable,'-c',fake],output,self.guard,self.policy,deadline=5))
        self.assertEqual(200,json.loads(output.read_text())['status_code'])

    def test_latency_baselines_do_not_mix_hosts(self):
        for _ in range(5): self.guard.feedback(200,elapsed=0.1,host='fast.test')
        for _ in range(5): self.guard.feedback(200,elapsed=3,host='slow.test')
        self.assertFalse(self.guard.state()['stopped'])

    def test_head_large_content_length_does_not_download_or_fail(self):
        response=Mock(status=200,headers={'Content-Length':'9999999'})
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        client=ProtectedHTTP(self.policy,self.guard)
        client.opener=Mock(); client.opener.open.return_value=response
        result=client.fetch('https://example.test/download',method='HEAD',limit=100)
        self.assertTrue(result['complete'])
        response.read.assert_not_called()

    def test_trickle_response_cannot_extend_transfer_indefinitely(self):
        clock=[0]
        class Trickle(io.BytesIO):
            status=200
            headers={}
            def read1(self,size):
                clock[0]+=1
                return super().read(1)
        response=Trickle(b'abcdef')
        client=ProtectedHTTP(self.policy,self.guard,timeout=2)
        client.opener=Mock(); client.opener.open.return_value=response
        with patch('recon81.guard.time.monotonic',side_effect=lambda:clock[0]):
            result=client.get('https://example.test/profile')
        self.assertFalse(result['complete'])
        self.assertEqual(b'',result['body'])
        self.assertTrue(response.closed)
        self.assertEqual(1,self.guard.state()['hosts']['example.test']['failures'])

    def test_crawl_preserves_links_without_requesting_mutation(self):
        client=Mock()
        client.get.return_value={'status':200,'headers':{'Content-Type':'text/html'},'body':b'<a href="/delete/1">bad</a><a href="/profile">good</a><script src="/main.js"></script>','complete':True}
        urls=crawl(['https://example.test/'],client,self.policy,max_pages=3,depth=1)
        self.assertIn('https://example.test/profile',urls)
        self.assertIn('https://example.test/main.js',urls)
        self.assertNotIn('https://example.test/delete/1',urls)
        self.assertFalse(any('/delete/' in c.args[0] for c in client.get.call_args_list))

    def test_js_cache_all_hits_never_falls_back_to_download(self):
        client=Mock()
        client.get.return_value={'status':200,'body':b'var ok=1;','complete':True}
        out=self.root/'js'; cache=self.root/'cache.jsonl'; mapping=self.root/'mapping.txt'
        self.assertEqual(1,download(['https://example.test/main.js'],client,self.policy,out,mapping,cache,min_free_bytes=0))
        client.reset_mock()
        self.assertEqual(0,download(['https://example.test/main.js'],client,self.policy,out,mapping,cache,min_free_bytes=0))
        client.get.assert_not_called()
        self.assertEqual(1,len(cached_keys(cache)))

    def test_expired_cache_is_revalidated_and_failed_download_not_cached(self):
        cache=self.root/'cache.jsonl'
        url='https://example.test/main.js'; key=hashlib.sha256(url.encode()).hexdigest()
        cache.write_text(json.dumps({'url_hash':key,'downloaded_at':time.time()-8*86400})+'\n')
        self.assertEqual(set(),cached_keys(cache))
        client=Mock(); client.get.return_value={'status':500,'body':b'','complete':False}
        self.assertEqual(0,download([url],client,self.policy,self.root/'js',self.root/'mapping',cache,min_free_bytes=0))
        self.assertEqual(set(),cached_keys(cache))

    def test_graphql_read_post_kept_mutations_and_large_queries_blocked(self):
        self.assertTrue(read_only_graphql(b'{"query":"query User { me { id } }","variables":{"first":20}}'))
        self.assertFalse(read_only_graphql(b'{"query":"mutation { deleteUser(id:1) }"}'))
        self.assertFalse(read_only_graphql(b'{"query":"{ users { id } }","variables":{"first":10000}}'))
        self.assertFalse(read_only_graphql(b'{"query":"{ users(first:10000) { id } }"}'))

    def test_screenshot_samples_hosts_without_losing_js_support(self):
        urls=['https://example.test/','https://example.test/profile','https://example.test/api/users','https://example.test/a.js','https://example.test/delete']
        pages=select_pages(urls,self.policy)
        self.assertEqual(2,len(pages))
        self.assertIn('https://example.test/',pages)

    def test_browser_gate_aborts_out_of_scope_and_mutation_before_fetch(self):
        client=Mock(); gate=BrowserGate(self.policy,client)
        for url,method,data in [('https://outside.test/','GET',None),('https://example.test/graphql','POST',b'{"query":"mutation { run }"}')]:
            request=Mock(url=url,method=method,post_data_buffer=data,resource_type='xhr',headers={})
            route=Mock(request=request)
            gate.handle(route); route.abort.assert_called_once()
        client.fetch.assert_not_called()

    def test_browser_gate_permits_read_graphql_and_no_auto_redirect_bypass(self):
        self.policy=NetworkPolicy(['example.test'],graphql_urls=['https://example.test/graphql'])
        client=Mock(); client.fetch.return_value={'status':200,'headers':{'Content-Type':'application/json'},'body':b'{"data":{}}','complete':True}
        gate=BrowserGate(self.policy,client)
        request=Mock(url='https://example.test/graphql',method='POST',post_data_buffer=b'{"query":"{ me { id } }"}',resource_type='xhr',headers={'Content-Type':'application/json'})
        route=Mock(request=request); gate.handle(route)
        self.assertTrue(client.fetch.call_args.kwargs['approved_read_post'])
        route.fulfill.assert_called_once()
        client.reset_mock(); client.fetch.return_value={'status':302,'headers':{'Location':'https://outside.test/'},'body':b'','complete':True}
        request=Mock(url='https://example.test/',method='GET',post_data_buffer=None,resource_type='document',headers={})
        route=Mock(request=request); gate.handle(route)
        self.assertIsNone(gate.document_redirect)
        self.assertEqual(1,client.fetch.call_count)
        route.abort.assert_called_once()

    def test_workflow_keeps_httpx_matrix_and_prevents_duplicate_runs(self):
        import re
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/passive_recon.yml').read_text()
        block=text.split('  httpx-live-probe:',1)[1].split('  screenshot-sample:',1)[0]
        self.assertEqual(20,len(re.findall(r"'[0-9]{2}'",block)))
        self.assertNotIn('max-parallel:',block)
        self.assertIn('cancel-in-progress: false',text)
        self.assertNotIn('apparmor_restrict_unprivileged_userns',text)
        self.assertNotIn('gowitness scan',text)
        self.assertIn('options: [balanced, passive, offline]',text)

    def test_legacy_report_has_no_target_network_client(self):
        text=(Path(__file__).resolve().parents[1]/'txt_to_excel.py').read_text()
        for needle in ('session.get(', 'requests.get(', 'ClientSession(', 'ssl=False'):
            self.assertNotIn(needle,text)

if __name__=='__main__': unittest.main()
