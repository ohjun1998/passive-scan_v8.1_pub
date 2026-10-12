#!/usr/bin/env python3
"""Keep Katana's JS-aware crawl; add explicit scope, exclusions and overload supervision."""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from recon81.core import private_write
from recon81.guard import RunGuard
from recon81.network_policy import NetworkPolicy, scope_from_file
from guarded_probe import supervise


def scope_regex(policy):
    hosts=[]
    for pattern in policy.scope.patterns:
        if pattern.startswith('*.'):
            hosts.append(r'(?:[a-z0-9-]+\.)*'+re.escape(pattern[2:]))
        else: hosts.append(re.escape(pattern))
    ports='|'.join(str(p) for p in sorted(policy.allowed_ports))
    return r'(?i)^https?://(?:'+'|'.join(hosts)+r')(?::(?:'+ports+r'))?(?:/|$)'


def exclusions():
    # Encode each ASCII letter alternative too, to exclude encoded action names before crawl.
    actions=['logout','signout','delete','remove','revoke','destroy','reset','activate','verify','confirm','send','trigger','execute','run','job','restart','shutdown','reboot','purge','flush','migrate','rebuild','restore','transfer','checkout','payment','refund','unsubscribe']
    encoded=[]
    for word in actions:
        encoded.append(''.join('(?:'+c+'|%'+format(ord(c),'02x')+')' for c in word))
    return r'(?i)(?:[/_.-](?:'+'|'.join(encoded)+r')(?:[/_.?&-]|$)|[?&](?:password|token|api[_-]?key|secret|session|csrf|xsrf|action|cmd|command|op|operation|task)=|%25|%2f|%5c)'


def command(binary, seeds, policy):
    return [binary,'-list',str(seeds),'-d','2','-c','2','-p','1','-rl','2','-retry','0','-timeout','8','-crawl-duration','120s','-mrs','1048576','-jc','-fs','fqdn','-cs',scope_regex(policy),'-cos',exclusions(),'-jsonl','-silent']


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seeds',type=Path,required=True)
    p.add_argument('--scope-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--state',type=Path,default=Path('results/crawl_guard.sqlite3'))
    p.add_argument('--katana',default='katana')
    p.add_argument('--active',action='store_true')
    args=p.parse_args()
    if not args.active: p.error('Target crawling requires --active')
    policy=NetworkPolicy(scope_from_file(args.scope_file))
    seeds=[]
    for line in args.seeds.read_text().splitlines():
        url=line.strip() if '://' in line else 'https://'+line.strip()
        if line.strip() and not policy.reason(url): seeds.append(url)
    ready=args.seeds.with_suffix('.reviewed.txt')
    private_write(ready,'\n'.join(seeds)+'\n' if seeds else '')
    raw=args.output.with_suffix('.jsonl')
    private_write(args.output,'')
    if not seeds: return 0
    guard=RunGuard(args.state,interval=0)
    try:
        status=supervise(command(args.katana,ready,policy),raw,guard,policy,deadline=150,kind='katana')
        found=set()
        for line in raw.read_text().splitlines():
            try:
                record=json.loads(line)
                url=(record.get('request') or {}).get('endpoint')
                if url and not policy.reason(url): found.add(url)
            except (ValueError,TypeError): continue
        private_write(args.output,'\n'.join(sorted(found))+'\n' if found else '')
        return status
    finally: guard.close()

if __name__=='__main__': raise SystemExit(main())
