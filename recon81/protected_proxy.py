"""Private loopback HTTP/HTTPS gateway for the controlled httpx/Katana commands.

CONNECT is terminated locally: every request, including redirects inside TLS,
passes NetworkPolicy and RunGuard before any connection to the target. Trust is
added only to the child environment, never to the user's certificate store.
"""
import base64
import hashlib
import ipaddress
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .core import private_write, safe_url
from .guard import ProtectedHTTP, GuardStopped
from .network_policy import PolicyDenied


HOP_HEADERS = {'connection','proxy-connection','proxy-authenticate','proxy-authorization',
               'keep-alive','transfer-encoding','te','trailer','upgrade','content-length'}


class ProtectedProxy:
    def __init__(self, policy, guard, client_factory=None):
        self.policy, self.guard = policy, guard
        self.client_factory = client_factory or (lambda: ProtectedHTTP(policy, guard))
        self.secret = secrets.token_urlsafe(32)
        self.authorization = 'Basic '+base64.b64encode(('scan:'+self.secret).encode()).decode()
        self.events = deque(maxlen=2048)
        self.responses = Counter()
        self.attempted_urls = set()
        self.response_lock = threading.Lock()
        self.lock = threading.Lock()
        self.contexts = {}
        self.temp = None
        self.server = None

    def _openssl(self, *args):
        subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)

    def __enter__(self):
        self.guard.check()
        self.temp = tempfile.TemporaryDirectory(prefix='passive-scan-gateway-')
        self.root = Path(self.temp.name)
        self.ca = self.root/'ca.pem'
        self.key = self.root/'ca.key'
        try:
            self._openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
                          '-days','1','-subj','/CN=PassiveScan ephemeral gateway','-addext','basicConstraints=critical,CA:TRUE',
                          '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(self.key),'-out',str(self.ca))
            for path in self.root.iterdir(): path.chmod(0o600)
            private_write(self.root/'config.yaml','{}\n')
            (self.root/'certs').mkdir(mode=0o700)
            owner = self
            class Handler(BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'
                tunnel = None
                def setup(self):
                    self.request.settimeout(10)
                    super().setup()
                def log_message(self, *args): pass
                def finish(self):
                    try: super().finish()
                    finally:
                        if self.tunnel is not None: self.connection.close()
                def fail(self, status):
                    self.send_response(status)
                    self.send_header('Content-Length','0')
                    self.send_header('Connection','close')
                    self.end_headers()
                    self.close_connection = True
                def authenticated(self):
                    return self.tunnel is not None or secrets.compare_digest(self.headers.get('Proxy-Authorization',''),owner.authorization)
                def do_CONNECT(self):
                    if not self.authenticated(): self.fail(407); return
                    try:
                        owner.guard.check()
                        parsed = urlsplit('https://'+self.path)
                        if parsed.path or parsed.query or parsed.fragment or not parsed.hostname:
                            raise PolicyDenied('invalid_connect_authority')
                        owner.policy.check('https://'+self.path+'/')
                        context = owner.tls_context(parsed.hostname)
                        self.send_response(200,'Connection Established'); self.end_headers(); self.wfile.flush()
                        self.rfile.close(); self.wfile.close()
                        self.connection = context.wrap_socket(self.connection,server_side=True)
                        self.rfile = self.connection.makefile('rb',self.rbufsize)
                        self.wfile = self.connection.makefile('wb',0)
                        self.tunnel = self.path
                        self.close_connection = False
                        self.handle_one_request()
                    except (PolicyDenied,GuardStopped):
                        if self.tunnel is None: self.fail(403)
                    except (OSError,ValueError): pass
                    finally: self.close_connection = True
                def forward(self):
                    if not self.authenticated(): self.fail(407); return
                    try:
                        if self.tunnel:
                            if not self.path.startswith('/') or self.path.startswith('//'):
                                raise PolicyDenied('invalid_tunnel_path')
                            url = 'https://'+self.tunnel+self.path
                        else:
                            url = self.path
                            if urlsplit(url).scheme != 'http': raise PolicyDenied('absolute_http_url_required')
                        owner.policy.check(url,self.command)
                        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length','0') != '0':
                            raise PolicyDenied('read_request_has_body')
                        client = owner.client_factory()
                        client.on_dispatch = owner.note_dispatch
                        result = client.fetch(url,method=self.command,headers=dict(self.headers),limit=1024*1024)
                        owner.events.append({'url':safe_url(url),'status':result['status'],'complete':result['complete']})
                        if not result['status'] or not result['complete']: self.fail(502); return
                        with owner.response_lock:
                            owner.responses[(url,result['status'])] += 1
                        self.send_response_only(result['status'])
                        connection_header = next((v for k,v in result['headers'].items() if k.lower()=='connection'), '')
                        hop = HOP_HEADERS | {x.strip().lower() for x in connection_header.split(',')}
                        for key,value in result['headers'].items():
                            if key.lower() not in hop and '\r' not in value and '\n' not in value:
                                self.send_header(key,value)
                        self.send_header('Content-Length',str(len(result['body'])))
                        self.send_header('Connection','close')
                        self.end_headers()
                        if self.command != 'HEAD': self.wfile.write(result['body'])
                    except PolicyDenied as error:
                        try: denied_url = safe_url(url)
                        except (ValueError,UnboundLocalError): denied_url = ''
                        owner.events.append({'url':denied_url,'policy_denied':str(error)})
                        self.fail(403)
                    except GuardStopped as error:
                        owner.events.append({'stop_reason':str(error)})
                        self.fail(429 if str(error)=='overload_http_429' else 503)
                    except (OSError,ValueError): self.fail(502)
                    finally: self.close_connection = True
                do_GET = forward
                do_HEAD = forward
                do_POST = forward
                do_PUT = forward
                do_PATCH = forward
                do_DELETE = forward
                do_OPTIONS = forward
            class Server(ThreadingHTTPServer):
                daemon_threads = False
                block_on_close = True
                slots = threading.BoundedSemaphore(32)
                def process_request(self, request, address):
                    if not self.slots.acquire(blocking=False):
                        self.shutdown_request(request); return
                    try: super().process_request(request,address)
                    except BaseException:
                        self.slots.release(); raise
                def process_request_thread(self, request, address):
                    try: super().process_request_thread(request,address)
                    finally: self.slots.release()
                def handle_error(self, request, client_address): pass
            self.server = Server(('127.0.0.1',0),Handler)
            self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
            self.thread.start()
            self.url = 'http://scan:'+self.secret+'@127.0.0.1:'+str(self.server.server_port)
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def tls_context(self, host):
        with self.lock:
            if host in self.contexts: return self.contexts[host]
            # CONNECT itself makes no target request. Limit local certificate work.
            if len(self.contexts) >= min(self.guard.max_requests, 1024):
                raise PolicyDenied('gateway_certificate_budget')
            stem = hashlib.sha256(host.encode()).hexdigest()
            key,csr,cert,ext = [self.root/(stem+suffix) for suffix in ('.key','.csr','.pem','.ext')]
            try:
                ipaddress.ip_address(host); san = 'IP:'+host
            except ValueError: san = 'DNS:'+host
            private_write(ext,'subjectAltName='+san+'\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
            self._openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=Gateway target','-keyout',str(key),'-out',str(csr))
            self._openssl('x509','-req','-in',str(csr),'-CA',str(self.ca),'-CAkey',str(self.key),'-set_serial','0x'+secrets.token_hex(16),'-days','1','-extfile',str(ext),'-out',str(cert))
            for path in (key,csr,cert): path.chmod(0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert,key)
            self.contexts[host] = context
            return context

    def command(self, argv):
        return [*argv,'-proxy',self.url,'-config',str(self.root/'config.yaml'),'-duc']

    def claim_response(self, url, status):
        """Match one child result to one unmodified target response, not a refusal."""
        with self.response_lock:
            key = (url,status)
            if not self.responses[key]: return False
            self.responses[key] -= 1
            return True

    def note_dispatch(self, url):
        self.attempted_urls.add(url)
        self.events.append({'url':safe_url(url),'event':'dispatch'})

    def environment(self):
        env = {k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy') and not k.startswith(('HTTPX_','KATANA_','PDCP_','PROJECTDISCOVERY_'))}
        env.update(HTTP_PROXY=self.url,HTTPS_PROXY=self.url,NO_PROXY='',SSL_CERT_FILE=str(self.ca),SSL_CERT_DIR=str(self.root/'certs'))
        return env

    def __exit__(self, *args):
        if self.server:
            self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
            self.server = None
        if self.temp:
            self.temp.cleanup(); self.temp = None
