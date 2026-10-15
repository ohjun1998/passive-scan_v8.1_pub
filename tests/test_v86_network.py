"""Network regression tests: every server binds only to loopback."""
import base64
import http.client
import json
import multiprocessing
import os
import subprocess
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.request import HTTPSHandler, ProxyHandler, build_opener
from guarded_probe import protected_supervise
from recon81.core import Inventory, normalize_record
from recon81.graphql_policy import read_only_graphql
from recon81.guard import GuardStopped, NoRedirect, ProtectedHTTP, RunGuard
from recon81.network_policy import NetworkPolicy
from recon81.protected_proxy import ProtectedProxy
from review_queue import build, executable, execute
from safe_screenshots import BrowserGate


def reserve_process(path, barrier, result):
    guard = RunGuard(path,max_requests=1,interval=0)
    try:
        barrier.wait()
        try: guard.reserve(); result.put('reserved')
        except GuardStopped: result.put('stopped')
    finally: guard.close()


class NetworkFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.hits = []
        hits = self.hits
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                hits.append(self.path)
                if self.path == '/redirect':
                    self.send_response(302); self.send_header('Location','/delete1'); self.end_headers(); return
                if self.path == '/truncated':
                    self.send_response(200); self.send_header('Content-Length','10'); self.end_headers(); self.wfile.write(b'abc'); return
                if self.path == '/chunked':
                    self.send_response(200); self.send_header('Transfer-Encoding','chunked'); self.end_headers(); self.wfile.write(b'5\r\nabc'); return
                body = b'{"reason":"denied"}' if self.path == '/denied' else b'<a href="/delete1">unsafe</a><a href="/ok">safe</a>'
                self.send_response(403 if self.path == '/denied' else 200)
                self.send_header('Content-Type','application/json' if self.path == '/denied' else 'text/html')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        self.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.worker = threading.Thread(target=self.server.serve_forever,daemon=True); self.worker.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.policy = NetworkPolicy(['127.0.0.1'],allowed_ports=[self.server.server_port])
        self.guard = RunGuard(self.root/'state',interval=0)
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join(timeout=2)
        self.guard.close(); self.temp.cleanup()
    def proxy_get(self, gateway, path, tls=False):
        if tls:
            context = ssl.create_default_context(cafile=str(gateway.ca))
            connection = http.client.HTTPSConnection('127.0.0.1',gateway.server.server_port,context=context,timeout=5)
            connection.set_tunnel('127.0.0.1',self.server.server_port,{'Proxy-Authorization':gateway.authorization})
            connection.request('GET',path)
        else:
            connection = http.client.HTTPConnection('127.0.0.1',gateway.server.server_port,timeout=5)
            connection.request('GET',self.url+path,headers={'Proxy-Authorization':gateway.authorization})
        result = connection.getresponse(); status = result.status; body = result.read(); connection.close()
        return status,body


class NetworkTests(NetworkFixture):
    def test_bounded_error_bodies_and_truncated_framing(self):
        client = ProtectedHTTP(self.policy,self.guard)
        denied = client.get(self.url+'/denied')
        self.assertEqual(403,denied['status']); self.assertTrue(denied['complete'])
        self.assertEqual({'reason':'denied'},json.loads(denied['body']))
        for path in ('/truncated','/chunked'):
            result = client.get(self.url+path)
            self.assertFalse(result['complete']); self.assertEqual(b'',result['body'])

    def test_byte_exhaustion_is_persisted_and_accounted(self):
        guard = RunGuard(self.root/'tiny',max_bytes=4,interval=0)
        try:
            with self.assertRaises(GuardStopped): guard.consume(5)
            self.assertEqual(5,guard.state()['bytes']); self.assertTrue(guard.state()['stopped'])
            with self.assertRaises(GuardStopped): guard.reserve()
        finally: guard.close()
        guard = RunGuard(self.root/'tiny',max_bytes=100,interval=0)
        try:
            with self.assertRaises(GuardStopped): guard.reserve()
        finally: guard.close()

    def test_transfer_cannot_read_past_shared_byte_budget(self):
        guard = RunGuard(self.root/'small',max_bytes=4,interval=0)
        try:
            with self.assertRaises(GuardStopped): ProtectedHTTP(self.policy,guard).get(self.url+'/ok')
            self.assertEqual(4,guard.state()['bytes']); self.assertTrue(guard.state()['stopped'])
            self.assertEqual(0,guard.state()['reserved_bytes'])
            with self.assertRaises(GuardStopped): ProtectedHTTP(self.policy,guard).get(self.url+'/again')
            self.assertEqual(['/ok'],self.hits)
        finally: guard.close()

    def test_reservations_are_atomic_across_processes(self):
        path = self.root/'shared'; guard = RunGuard(path,max_requests=1,interval=0); guard.close()
        context = multiprocessing.get_context('spawn')
        barrier = context.Barrier(2); result = context.Queue()
        workers = [context.Process(target=reserve_process,args=(path,barrier,result)) for _ in range(2)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(timeout=5); self.assertEqual(0,worker.exitcode)
        self.assertEqual(['reserved','stopped'],sorted(result.get(timeout=1) for _ in workers))
        guard = RunGuard(path,max_requests=1,interval=0)
        try: self.assertEqual(1,guard.state()['requests'])
        finally: guard.close()

    def test_encoded_costly_path_shares_budget(self):
        for path in ('/export','/%65xport','/e%78port'): self.guard.reserve(self.url+path)
        with self.assertRaisesRegex(GuardStopped,'costly_request'): self.guard.reserve(self.url+'/%2565xport')
        self.guard.reserve(self.url+'/profile')

    def test_graphql_needs_reviewed_endpoint_content_type_and_envelope(self):
        body = b'{"query":"{ me { id } }"}'
        self.assertTrue(read_only_graphql(body))
        self.assertFalse(read_only_graphql(body,'text/plain'))
        self.assertFalse(read_only_graphql(b'{"query":"{ me { id } }","displayName":"changed"}'))
        self.assertFalse(read_only_graphql(b'{"query":"mutation { update }","query":"{ me { id } }"}'))
        self.assertFalse(read_only_graphql(b'{"query":"{ me { id } }","variables":[]}'))
        self.assertFalse(read_only_graphql(b'{"query":"{users(first:100){posts(first:100){comments(first:100){id}}}}"}'))
        endpoint = self.url+'/graphql'
        record = normalize_record(endpoint,'POST',{'Content-Type':'application/json'},body,observed=True)
        self.assertFalse(executable(record,self.policy)[0])
        policy = NetworkPolicy(['127.0.0.1'],allowed_ports=[self.server.server_port],graphql_urls=[endpoint])
        self.assertTrue(executable(record,policy)[0])
        client = Mock()
        route = Mock(request=SimpleNamespace(url=self.url+'/profile',method='POST',post_data_buffer=body,headers={'Content-Type':'application/json'},resource_type='fetch'))
        BrowserGate(policy,client).handle(route)
        route.abort.assert_called_once(); client.fetch.assert_not_called()
        client.guard = SimpleNamespace(max_requests=2)
        with Inventory(self.root/'graphql-inventory') as inventory:
            inventory.add(record)
            plan = build(list(inventory.records()),policy)
            with self.assertRaises(ValueError):
                execute(inventory,plan,[record['observation_id']],client,policy,'reviewer',headers={'content-type':'text/plain'})
        client.fetch.assert_not_called()

    def test_resource_redirect_drops_credentials_when_scheme_changes(self):
        policy = NetworkPolicy(['example.test'])
        client = Mock()
        client.fetch.side_effect = [
            {'status':302,'headers':{'Location':'http://example.test/main.js'},'body':b'','complete':True},
            {'status':200,'headers':{'Content-Type':'application/javascript'},'body':b'var ok=1','complete':True}]
        request = SimpleNamespace(url='https://example.test/main.js',method='GET',post_data_buffer=None,
                                  headers={'Authorization':'Bearer FIXTURE','Cookie':'session=FIXTURE'},resource_type='script')
        BrowserGate(policy,client).handle(Mock(request=request))
        redirected_headers = client.fetch.call_args_list[1].args[2]
        self.assertEqual({},redirected_headers)

    def test_gateway_blocks_policy_before_http_dispatch_and_redirect(self):
        with ProtectedProxy(self.policy,self.guard) as gateway:
            for path in ('/delete1','/%64%65%6c%65%74%65/1','/a?limit=10000','/a?otp=1','/a?do=remove','/a.sql'):
                self.assertEqual(403,self.proxy_get(gateway,path)[0])
            self.assertEqual([],self.hits); self.assertEqual(0,self.guard.state()['requests'])
            self.assertEqual(302,self.proxy_get(gateway,'/redirect')[0])
            self.assertEqual(403,self.proxy_get(gateway,'/delete1')[0])
            self.assertEqual(200,self.proxy_get(gateway,'/ok')[0])
            self.assertEqual(['/redirect','/ok'],self.hits)
            self.assertEqual(2,self.guard.state()['requests'])
            connection = http.client.HTTPConnection('127.0.0.1',gateway.server.server_port,timeout=5)
            connection.request('GET',self.url+'/without-auth')
            self.assertEqual(407,connection.getresponse().status); connection.close()

    def test_gateway_checks_each_https_request_after_connect(self):
        with ProtectedProxy(self.policy,self.guard) as gateway:
            self.server.socket = gateway.tls_context('127.0.0.1').wrap_socket(self.server.socket,server_side=True)
            def client_factory():
                client = ProtectedHTTP(self.policy,self.guard)
                client.opener = build_opener(ProxyHandler({}),NoRedirect(),HTTPSHandler(context=ssl.create_default_context(cafile=str(gateway.ca))))
                return client
            gateway.client_factory = client_factory
            self.assertEqual(200,self.proxy_get(gateway,'/ok',tls=True)[0])
            self.assertEqual(403,self.proxy_get(gateway,'/delete1',tls=True)[0])
            self.assertEqual(['/ok'],self.hits)
            self.assertEqual(1,self.guard.state()['requests'])

    def test_gateway_byte_cap_stops_next_target_request(self):
        guard = RunGuard(self.root/'proxy-small',max_bytes=4,interval=0)
        try:
            with ProtectedProxy(self.policy,guard) as gateway:
                self.assertEqual(503,self.proxy_get(gateway,'/ok')[0])
                self.assertEqual(503,self.proxy_get(gateway,'/again')[0])
                self.assertEqual(['/ok'],self.hits); self.assertEqual(4,guard.state()['bytes'])
        finally: guard.close()

    def test_external_child_uses_gateway_with_actual_budget(self):
        guard = RunGuard(self.root/'tool',max_requests=2,interval=0)
        script = '''import base64,http.client,json,os,sys,time
from urllib.parse import urlsplit
proxy=urlsplit(os.environ['HTTP_PROXY'])
auth='Basic '+base64.b64encode((proxy.username+':'+proxy.password).encode()).decode()
for path in ['/ok?i=1','/ok?i=2','/ok?i=3']:
 c=http.client.HTTPConnection(proxy.hostname,proxy.port,timeout=5)
 u=sys.argv[1]+path;c.request('GET',u,headers={'Proxy-Authorization':auth})
 r=c.getresponse();r.read();print(json.dumps({'url':u,'status_code':r.status}),flush=True);c.close()
time.sleep(1)
'''
        try:
            output = self.root/'tool.jsonl'
            selected = [self.url+'/ok?i='+str(i) for i in (1,2,3)]
            deferred = self.root/'deferred.txt'
            self.assertEqual(3,protected_supervise([sys.executable,'-c',script,self.url],output,guard,self.policy,deadline=5,selected_urls=selected,deferred_path=deferred))
            self.assertEqual(['/ok?i=1','/ok?i=2'],self.hits)
            self.assertEqual(2,guard.state()['requests'])
            self.assertGreater(guard.state()['bytes'],0)
            self.assertEqual('request_budget_exhausted',json.loads(output.with_suffix('.network.json').read_text())['guard']['reason'])
            self.assertEqual([selected[2]],deferred.read_text().splitlines())
        finally: guard.close()

    def test_synthetic_gateway_error_is_not_target_evidence(self):
        with ProtectedProxy(self.policy,self.guard) as gateway:
            self.assertEqual(502,self.proxy_get(gateway,'/truncated')[0])
            self.assertFalse(gateway.claim_response(self.url+'/truncated',502))
            self.assertFalse(gateway.claim_response(self.url+'/truncated',200))
            self.assertEqual(200,self.proxy_get(gateway,'/ok')[0])
            self.assertTrue(gateway.claim_response(self.url+'/ok',200))
            self.assertFalse(gateway.claim_response(self.url+'/ok',503))
            self.assertFalse(gateway.claim_response(self.url+'/ok',200))
            self.assertTrue(any(e.get('status')==200 and e.get('complete') is False for e in gateway.events))

    def test_stopped_guard_never_starts_child(self):
        try: self.guard.stop('manual_stop')
        except GuardStopped: pass
        marker = self.root/'should-not-exist'
        code = 'from pathlib import Path;Path('+repr(str(marker))+').touch()'
        self.assertEqual(3,protected_supervise([sys.executable,'-c',code],self.root/'stopped',self.guard,self.policy))
        self.assertFalse(marker.exists())

    def test_secret_scanner_redacts_and_reports_failure(self):
        script = Path(__file__).resolve().parents[1]/'scan_trufflehog.sh'
        binary = self.root/'trufflehog'
        binary.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"DetectorName":"Fixture","Raw":"SYNTHETIC_SECRET","SourceMetadata":{"Data":{"Filesystem":{"file":"main.js"}}}}\'\n')
        binary.chmod(0o700)
        target = self.root/'results/example.test_js_files_00'; target.mkdir(parents=True)
        env = dict(os.environ,PATH=str(self.root)+os.pathsep+os.environ['PATH'])
        result = subprocess.run(['bash',str(script),'00'],cwd=self.root,env=env,capture_output=True)
        self.assertEqual(0,result.returncode)
        output = self.root/'results/example.test_trufflehog_00.txt'
        self.assertNotIn('SYNTHETIC_SECRET',output.read_text()); self.assertIn('[REDACTED]',output.read_text())
        self.assertEqual(0o600,output.stat().st_mode & 0o777)
        self.assertEqual([],list((self.root/'results').glob('.trufflehog.*')))
        binary.write_text('#!/bin/sh\nexit 7\n')
        result = subprocess.run(['bash',str(script),'00'],cwd=self.root,env=env,capture_output=True)
        self.assertEqual(1,result.returncode); self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
