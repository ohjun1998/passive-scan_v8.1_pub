"""Optional Chromium integration against a loopback-only fixture server."""
import json
import faulthandler
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from recon81.network_policy import NetworkPolicy
from recon81.guard import RunGuard, ProtectedHTTP
from safe_screenshots import BrowserGate, configure_context


@unittest.skipUnless(os.environ.get('RUN_BROWSER_TESTS')=='1', 'Enable RUN_BROWSER_TESTS with installed Chromium')
class BrowserRuntimeTests(unittest.TestCase):
    def test_dashboard_filters_comparison_and_review_export_without_target_requests(self):
        faulthandler.dump_traceback_later(30,exit=True)
        from playwright.sync_api import sync_playwright,expect
        from recon81.core import Inventory,normalize_record
        from recon81.context import attach_context
        from recon81.reports import generate
        requested=[]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with Inventory(root/'db') as inv:
                for actor in ('user-a','user-b'):
                    r=normalize_record('https://example.test/api/orders/123','GET',body=b'',response={'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'id':123,'ownerId':actor})})
                    inv.add(attach_context(r,{'actor':actor,'tenant':'org-a','scenario':'주문 조회','capture_id':'flow-'+actor}))
                generate(list(inv.records()),root/'report')
            body=(root/'report/index.html').read_bytes()
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                with sync_playwright() as pw:
                    browser=pw.chromium.launch();page=browser.new_page()
                    page.on('request',lambda r:requested.append(r.url))
                    page.goto(f'http://127.0.0.1:{server.server_port}/')
                    expect(page.locator('#rows tr')).to_have_count(2)
                    page.get_by_role('button',name='계정 비교',exact=True).click()
                    expect(page.locator('#diffRows')).to_contain_text('$.ownerId')
                    page.get_by_role('button',name='커버리지',exact=True).click()
                    expect(page.locator('#coverageRows')).to_contain_text('user-a, user-b')
                    page.get_by_role('button',name='요청 / 후보',exact=True).click()
                    page.locator('#actor').select_option('user-a')
                    expect(page.locator('#rows tr')).to_have_count(1)
                    expect(page.locator('#metadata')).to_contain_text('user-a')
                    page.locator('#reviewState').select_option('confirmed')
                    page.get_by_role('button',name='이 화면에 적용',exact=True).click()
                    expect(page.locator('#reviewMessage')).to_contain_text('증거 메모')
                    page.locator('#reviewState').select_option('deferred')
                    page.locator('#reviewNote').fill('Synthetic fixture: additional response evidence needed')
                    page.get_by_role('button',name='이 화면에 적용',exact=True).click()
                    with page.expect_download() as pending:
                        page.get_by_role('button',name='검토 변경 내보내기',exact=True).click()
                    download=pending.value;path=root/'edits.json';download.save_as(path)
                    edits=json.loads(path.read_text());self.assertEqual('deferred',edits['reviews'][0]['state'])
                    self.assertTrue(page.screenshot().startswith(b'\x89PNG'))
                    browser.close()
                self.assertTrue(all(url.startswith(f'http://127.0.0.1:{server.server_port}/') for url in requested))
            finally:
                server.shutdown();server.server_close();worker.join(timeout=2)
                faulthandler.cancel_dump_traceback_later()

    def test_js_read_query_preserved_and_unsafe_requests_never_reach_server(self):
        faulthandler.dump_traceback_later(30,exit=True)
        from playwright.sync_api import sync_playwright
        hits=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                hits.append(('GET',self.path))
                if self.path=='/redirect':
                    self.send_response(302)
                    self.send_header('Location',f'http://localhost:{self.server.server_port}/outside')
                    self.end_headers(); return
                body=f'''<h1 id="result">loading</h1><script>
                fetch('/graphql',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{query:'{{ me {{ id }} }}'}})}})
                  .then(r=>r.json()).then(r=>document.querySelector('#result').textContent='id='+r.data.me.id);
                fetch('/graphql',{{method:'POST',body:JSON.stringify({{query:'mutation {{ deleteUser }}'}})}}).catch(()=>{{}});
                fetch('/delete/1').catch(()=>{{}});
                fetch('http://localhost:{self.server.server_port}/outside').catch(()=>{{}});
                new WebSocket('ws://127.0.0.1:{self.server.server_port}/socket');
                </script>'''.encode()
                self.send_response(200); self.send_header('Content-Type','text/html')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                payload=self.rfile.read(int(self.headers.get('Content-Length','0')))
                hits.append(('POST',self.path,json.loads(payload)))
                body=b'{"data":{"me":{"id":7}}}'
                self.send_response(200); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        try:
            with tempfile.TemporaryDirectory() as temp, sync_playwright() as pw:
                policy=NetworkPolicy(['127.0.0.1'],allowed_ports=[server.server_port])
                guard=RunGuard(Path(temp)/'state.db',interval=0)
                try:
                    browser=pw.chromium.launch()
                    context=browser.new_context(service_workers='block')
                    gate=BrowserGate(policy,ProtectedHTTP(policy,guard))
                    configure_context(context,gate)
                    page=context.new_page()
                    page.goto(f'http://127.0.0.1:{server.server_port}/',wait_until='domcontentloaded')
                    page.wait_for_function("document.querySelector('#result').textContent==='id=7'")
                    self.assertTrue(page.screenshot().startswith(b'\x89PNG'))
                    with self.assertRaises(Exception):
                        page.goto(f'http://127.0.0.1:{server.server_port}/redirect',timeout=5000)
                    self.assertIsNone(gate.document_redirect)
                    context.close(); browser.close()
                    self.assertEqual([('GET','/'),('POST','/graphql',{'query':'{ me { id } }'}),('GET','/redirect')],hits)
                finally: guard.close()
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=2)
            faulthandler.cancel_dump_traceback_later()

