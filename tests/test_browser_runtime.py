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

