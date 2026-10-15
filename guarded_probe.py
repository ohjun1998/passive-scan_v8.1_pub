#!/usr/bin/env python3
"""Policy-filter and supervise httpx. Retains -rl 10 and -t 5; no automatic retry."""
import argparse
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from recon81.core import private_write
from recon81.guard import RunGuard, GuardStopped
from recon81.network_policy import NetworkPolicy, scope_from_file


def command(binary, path):
    return [binary,'-l',str(path),'-sc','-td','-server','-random-agent','-rl','10','-t','5','-timeout','5','-retries','0','-no-fallback-scheme','-response-size-to-read','1048576','-max-host-error','3','-x','GET','-rt','-irh','-probe','-json','-silent']


def seconds(value):
    try:
        if isinstance(value,(float,int)):
            return float(value)
        s=str(value)
        if s.endswith('ms'): return float(s[:-2])/1000
        if s.endswith('s'): return float(s[:-1])
        return float(s)
    except ValueError:
        return 0


def supervise(argv, output, guard, policy, deadline=1200, kind="httpx", env=None, transport=None):
    guard.check()
    child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env=env,start_new_session=True)
    events=selectors.DefaultSelector()
    events.register(child.stdout,selectors.EVENT_READ,'stdout')
    events.register(child.stderr,selectors.EVENT_READ,'stderr')
    buffers={'stdout':b'', 'stderr':b''}
    started=time.monotonic()
    try:
        with open(output,'w',encoding='utf-8') as stream:
            Path(output).chmod(0o600)
            while events.get_map() or child.poll() is None:
                guard.check()
                if time.monotonic()-started > deadline:
                    raise GuardStopped('probe_deadline')
                for key,_ in events.select(timeout=0.25):
                    chunk=os.read(key.fileobj.fileno(),65536)
                    if not chunk:
                        events.unregister(key.fileobj)
                    buffers[key.data]+=chunk
                    if len(buffers[key.data])>4*1024*1024:
                        raise GuardStopped('tool_output_limit')
                    lines=buffers[key.data].split(b'\n')
                    buffers[key.data]=lines.pop() if chunk else b''
                    for raw in lines:
                        line=raw.decode('utf-8',errors='replace')
                        if key.data=='stderr':
                            if transport is None and any(s in line.lower() for s in ('timed out','timeout','deadline exceeded')):
                                guard.feedback(failed=True)
                            continue
                        try:
                            result=json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(result,dict): continue
                        if kind == 'katana':
                            response = result.get('response') or {}
                            url = (result.get('request') or {}).get('endpoint') or ''
                            status = int(response.get('status_code') or 0)
                            failed = bool(result.get('error'))
                        else:
                            response = result
                            url = result.get('input') or result.get('url') or ''
                            status = int(result.get('status_code') or 0)
                            failed = bool(result.get('failed') or result.get('error'))
                        if transport is not None and not transport.claim_response(url,status):
                            # A proxy refusal is not a target response. Preserve
                            # its stop reason in the separate transport ledger.
                            continue
                        if url and policy.reason(url):
                            if kind == 'katana' and not status: continue
                            raise GuardStopped('unexpected_probe_destination')
                        if transport is not None:
                            result['transport']='protected_gateway'
                            line=json.dumps(result,ensure_ascii=False)
                        headers=response.get('headers') or response.get('header') or response.get('response_headers') or {}
                        if not isinstance(headers,dict): headers={}
                        retry=next((str(v) for k,v in headers.items() if k.lower()=='retry-after'),'')
                        stream.write(line+'\n')
                        stream.flush()
                        if transport is None:
                            guard.feedback(status,seconds(response.get('time') or response.get('response_time') or 0),failed,retry,host=urlsplit(url).netloc)
        return child.wait()
    except GuardStopped:
        print(kind+' stopped by protection; no automatic retry or resume.')
        return 3
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL); child.wait()
        events.close()
        child.stdout.close(); child.stderr.close()


def protected_supervise(argv, output, guard, policy, deadline=1200, kind='httpx', selected_urls=(), deferred_path=None):
    """Production entry point: the tool never receives an unguarded HTTP proxy."""
    from recon81.protected_proxy import ProtectedProxy
    gateway = ProtectedProxy(policy,guard)
    try:
        with gateway:
            return supervise(gateway.command(argv),output,guard,policy,deadline,kind,
                             env=gateway.environment(),transport=gateway)
    except GuardStopped:
        return 3
    finally:
        # This ledger records target transport evidence even if the child is
        # stopped before it can print its final overloaded response.
        state = guard.state()
        deferred = sorted(set(selected_urls)-gateway.attempted_urls)
        if deferred_path is not None:
            previous = set(Path(deferred_path).read_text().splitlines()) if Path(deferred_path).exists() else set()
            private_write(deferred_path,'\n'.join(sorted(previous|set(deferred)))+('\n' if previous or deferred else ''))
        private_write(Path(output).with_suffix('.network.json'),json.dumps({'guard':state,'events':list(gateway.events),
            'selected_not_dispatched':len(deferred),'deferred_reason':(state['reason'] or 'tool_finished_without_dispatch') if deferred else ''},ensure_ascii=False,indent=2))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--scope-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--state',type=Path,default=Path('results/probe_guard.sqlite3'))
    p.add_argument('--httpx',default='httpx')
    p.add_argument('--max-urls',type=int,default=1000)
    p.add_argument('--active',action='store_true')
    args=p.parse_args()
    if not args.active: p.error('Target probing requires --active')
    if not 1<=args.max_urls<=100000: p.error('--max-urls must be 1..100000')
    policy=NetworkPolicy(scope_from_file(args.scope_file))
    candidates=sorted({u.strip() for u in args.input.read_text().splitlines() if u.strip() and not policy.reason(u.strip())})
    urls=candidates[:args.max_urls]
    private_write(args.output.with_suffix('.deferred.txt'),'\n'.join(candidates[args.max_urls:]))
    ready=args.input.with_suffix('.reviewed.txt')
    private_write(ready,'\n'.join(urls)+'\n' if urls else '')
    private_write(args.output,'')
    if not urls: return 0
    guard=RunGuard(args.state,interval=0)
    try: return protected_supervise(command(args.httpx,ready),args.output,guard,policy,selected_urls=urls,deferred_path=args.output.with_suffix('.deferred.txt'))
    finally: guard.close()

if __name__=='__main__':
    raise SystemExit(main())
