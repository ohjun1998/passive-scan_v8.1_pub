#!/usr/bin/env python3
"""Bounded HTML crawler. Every request passes policy and budget checks. No JS/forms."""
import argparse
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from recon81.core import private_write
from recon81.network_policy import NetworkPolicy, scope_from_file, PolicyDenied
from recon81.guard import RunGuard, ProtectedHTTP, GuardStopped


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('a', 'link') and attrs.get('href'):
            self.links.append(attrs['href'])
        elif tag == 'script' and attrs.get('src'):
            self.links.append(attrs['src'])


def crawl(seeds, client, policy, max_pages=100, depth=2):
    queue = deque((u, 0) for u in seeds)
    seen, found = set(), set()
    while queue and len(seen) < max_pages:
        url, level = queue.popleft()
        p = urlsplit(url)
        url = urlunsplit((p.scheme,p.netloc,p.path or '/',p.query,''))
        if url in seen or policy.reason(url):
            continue
        seen.add(url)
        found.add(url)
        try:
            result = client.get(url)
        except GuardStopped as error:
            if 'budget_exhausted' in str(error):
                break
            raise
        if not result['complete'] or result['status'] != 200:
            continue
        mime = next((v for k,v in result['headers'].items() if k.lower()=='content-type'),'')
        if 'html' not in mime:
            continue
        parser=Links()
        parser.feed(result['body'].decode('utf-8',errors='replace'))
        for link in parser.links[:1000]:
            absolute=urljoin(url,link)
            if not policy.reason(absolute):
                found.add(absolute)
                if level < depth and not urlsplit(absolute).path.lower().endswith('.js'):
                    queue.append((absolute,level+1))
    return sorted(found)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seeds',type=Path,required=True)
    p.add_argument('--scope-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--state',type=Path,default=Path('results/active_guard.sqlite3'))
    p.add_argument('--active',action='store_true',help='Explicitly enable target HTTP requests')
    args=p.parse_args()
    if not args.active:
        p.error('Target requests require --active')
    policy=NetworkPolicy(scope_from_file(args.scope_file))
    guard=RunGuard(args.state)
    try:
        seeds=[x.strip() if '://' in x else 'https://'+x.strip() for x in args.seeds.read_text().splitlines() if x.strip()]
        private_write(args.output,'\n'.join(crawl(seeds,ProtectedHTTP(policy,guard),policy))+'\n')
    except GuardStopped:
        print('Crawl stopped by overload protection; no automatic retry.')
        return 3
    finally:
        guard.close()
    return 0

if __name__=='__main__':
    raise SystemExit(main())
