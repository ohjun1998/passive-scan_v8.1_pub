#!/usr/bin/env python3
"""Sample browser screenshots with JS support and bounded, policy-gated networking."""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urljoin
from recon81.core import private_write
from recon81.guard import RunGuard, ProtectedHTTP, GuardStopped
from recon81.network_policy import NetworkPolicy, scope_from_file
from recon81.graphql_policy import read_only_graphql


def origin(url):
    parsed=urlsplit(url)
    return parsed.scheme,parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80)


def select_pages(urls, policy, max_pages=30, per_host=2):
    hosts=defaultdict(int)
    selected=[]
    for url in sorted(set(urls),key=lambda u:(len(urlsplit(u).path),len(u),u)):
        p=urlsplit(url)
        if policy.reason(url) or p.path.lower().endswith(('.js','.json','.css','.png','.jpg','.svg')):
            continue
        if p.path.startswith('/api/'):
            continue
        if hosts[p.netloc]>=per_host: continue
        hosts[p.netloc]+=1
        selected.append(url)
        if len(selected)>=max_pages: break
    return selected


class BrowserGate:
    def __init__(self, policy, client, max_requests=100):
        self.policy,self.client=policy,client
        self.remaining=max_requests
        self.stopped=False
        self.stop_reason=''
        self.visited=set()
        self.document_redirect=None

    def handle(self, route):
        request=route.request
        if self.stopped or self.remaining<=0 or request.resource_type in ('media','websocket'):
            route.abort(); return
        method=request.method.upper()
        data=request.post_data_buffer
        read_post=method=='POST' and self.policy.allows_graphql(request.url,request.headers,data)
        if method not in ('GET','HEAD') and not read_post:
            route.abort(); return
        if self.policy.reason(request.url,'GET' if read_post else method):
            route.abort(); return
        self.remaining-=1
        try:
            result=self.client.fetch(request.url,method,request.headers,data,approved_read_post=read_post,limit=2*1024*1024)
            if result['status']==0 or not result['complete']:
                route.abort(); return
            headers=result['headers']
            if 300<=result['status']<400:
                location=next((v for k,v in headers.items() if k.lower()=='location'),None)
                target=urljoin(request.url,location or '')
                if request.resource_type == 'document':
                    if location and not self.policy.reason(target): self.document_redirect = target
                    route.abort(); return
                # Resource redirects are fetched through the same policy and budget checks.
                for _ in range(3):
                    if method not in ('GET','HEAD') or not location or target in self.visited or self.policy.reason(target):
                        route.abort(); return
                    self.visited.add(target)
                    if self.remaining<=0: route.abort(); return
                    self.remaining-=1
                    redirect_headers=request.headers
                    if origin(target) != origin(request.url):
                        redirect_headers={k:v for k,v in redirect_headers.items() if k.lower() not in ('authorization','cookie')}
                    result=self.client.fetch(target,method,redirect_headers,limit=2*1024*1024)
                    if result['status']==0 or not result['complete']: route.abort(); return
                    if not 300<=result['status']<400: break
                    location=next((v for k,v in result['headers'].items() if k.lower()=='location'),None)
                    target=urljoin(target,location or '')
                if 300<=result['status']<400: route.abort(); return
                # A fulfilled redirect keeps the original URL; resolve relative HTML resources at the final URL.
                if 'text/html' in next((v for k,v in result['headers'].items() if k.lower()=='content-type'),''):
                    route.abort(); return  # HTML redirects need a direct final URL in the reviewed list.
            headers={k:v for k,v in result['headers'].items() if k.lower() not in ('content-length','transfer-encoding')}
            route.fulfill(status=result['status'],headers=headers,body=result['body'])
        except GuardStopped as error:
            self.stop_reason=str(error)
            self.stopped=self.stop_reason != 'costly_request_budget_exhausted'
            route.abort()
        except Exception:
            # Never bypass the policy when a renderer request fails.
            route.abort()


def configure_context(context, gate):
    context.route('**/*',gate.handle)
    # A routed socket stays disconnected from the server unless connect_to_server()
    # is called. Avoid synchronous close() inside the websocket callback: current
    # Playwright dispatch can deadlock there. Worker sockets use this route too.
    context.route_web_socket('**/*',lambda socket: None)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--urls',type=Path,required=True)
    p.add_argument('--scope-file',type=Path,required=True)
    p.add_argument('--output',type=Path,default=Path('results/screenshots'))
    p.add_argument('--max-pages',type=int,default=30)
    p.add_argument('--disable-js',action='store_true')
    p.add_argument('--graphql-url',action='append',default=[],help='Exact reviewed GraphQL endpoint; JSON query operations only')
    p.add_argument('--active',action='store_true')
    args=p.parse_args()
    if not args.active: p.error('Screenshots require --active')
    if not 1<=args.max_pages<=100: p.error('--max-pages must be 1..100')
    from playwright.sync_api import sync_playwright
    policy=NetworkPolicy(scope_from_file(args.scope_file),graphql_urls=args.graphql_url)
    guard=RunGuard(args.output.parent/'screenshot_guard.sqlite3',max_requests=1000,max_bytes=50*1024*1024,interval=0.5)
    client=ProtectedHTTP(policy,guard)
    args.output.mkdir(parents=True,exist_ok=True)
    records=[]
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True)
            for url in select_pages(args.urls.read_text().splitlines(),policy,args.max_pages):
                guard.check()
                context=browser.new_context(java_script_enabled=not args.disable_js,service_workers='block')
                gate=BrowserGate(policy,client)
                configure_context(context,gate)
                page=context.new_page()
                try:
                    navigate=url
                    visited=set()
                    for _ in range(4):
                        if navigate in visited: raise ValueError('Redirect loop')
                        visited.add(navigate)
                        gate.document_redirect=None
                        try: page.goto(navigate,wait_until='domcontentloaded',timeout=20000)
                        except Exception:
                            if not gate.document_redirect: raise
                        if not gate.document_redirect: break
                        navigate=gate.document_redirect
                    else: raise ValueError('Redirect limit')
                    page.wait_for_timeout(1500)
                    if gate.stopped: raise GuardStopped(gate.stop_reason)
                    name=hashlib.sha256(url.encode()).hexdigest()+'.png'
                    page.screenshot(path=str(args.output/name))
                    records.append({'url':url,'file':name})
                except GuardStopped: raise
                except Exception:
                    if gate.stopped: raise GuardStopped(gate.stop_reason)
                    records.append({'url':url,'error':'navigation_or_render_failed'})
                finally: context.close()
            browser.close()
    except GuardStopped as error:
        print('Screenshot run stopped: '+str(error)+'; partial results retained, no automatic reshoot.')
        return 0 if str(error) in ('request_budget_exhausted','byte_budget_exhausted') else 3
    finally:
        private_write(args.output/'manifest.json',json.dumps(records,ensure_ascii=False,indent=2))
        guard.close()
    return 0

if __name__=='__main__': raise SystemExit(main())
