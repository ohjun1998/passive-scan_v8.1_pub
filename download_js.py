#!/usr/bin/env python3
"""Bounded scoped JS downloader with collision-free filenames and source mappings."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from recon81.core import Scope, private_write, safe_url

LIMIT = 2 * 1024 * 1024


class ScopedRedirect(HTTPRedirectHandler):
    def __init__(self, scope):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.scope.allows(newurl):
            raise URLError('Out of scope redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--urls', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mapping', type=Path, required=True)
    parser.add_argument('--scope', action='append', required=True)
    args = parser.parse_args()
    scope = Scope(args.scope)
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    urls = sorted(set(args.urls.read_text(encoding='utf-8').splitlines()))[:1000]
    def download(url):
        if not scope.allows(url):
            return None
        name = hashlib.sha256(url.encode()).hexdigest() + '.js'
        try:
            with build_opener(ScopedRedirect(scope)).open(Request(url, headers={'User-Agent': 'PassiveScan/8.1'}), timeout=5) as response:
                data = response.read(LIMIT + 1)
                if len(data) > LIMIT:
                    return None
            target = args.output / name
            with open(target, 'wb') as stream:
                stream.write(data)
            target.chmod(0o600)
            return name + '\t' + safe_url(url)
        except (OSError, ValueError):
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rows = [r for r in pool.map(download, urls) if r]
    private_write(args.mapping, '\n'.join(rows) + ('\n' if rows else ''))
    print('Downloaded JS files: ' + str(len(rows)))


if __name__ == '__main__':
    main()
