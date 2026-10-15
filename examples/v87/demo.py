#!/usr/bin/env python3
"""Synthetic mixed-type leads and benign controls; no model or target requests."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from recon81.context import attach_context
from recon81.core import normalize_record
from recon81.reports import generate
from recon81.candidate_report import create_recommendations


def make(path, response, mime='application/json', actor=None, expected='unknown'):
    record = normalize_record('https://example.test' + path, 'GET', body=b'', response={
        'status': 200, 'headers': {'Content-Type': mime},
        'body': json.dumps(response) if isinstance(response, dict) else response},
        include_text=True, source='synthetic_v87_demo')
    return attach_context(record, {'actor': actor, 'expected_access': expected} if actor else {})


def fixture():
    return [
        make('/orders/102', {'ownerId': 'bob', 'total': 25}, actor='alice', expected='deny'),
        make('/orders/102', {'ownerId': 'bob', 'total': 25}, actor='bob', expected='allow'),
        make('/admin/export', {'admin_export': ['restricted']}, actor='alice', expected='deny'),
        make('/search?q=%3Cdemo-marker%3E', '<html><body><demo-marker></body></html>', 'text/html'),
        make('/lookup?name=sample', 'SQLSTATE[42000]: synthetic database error', 'text/plain'),
        make('/profile', {'email': 'demo@example.test', 'password_hash': 'synthetic-only'}),
        make('/config', {'client_secret': 'synthetic-placeholder'}),
        make('/safe?q=%3Cdemo-marker%3E', '<html>&lt;demo-marker&gt;</html>', 'text/html'),
        make('/text?q=demo-marker', '<html><p>demo-marker</p></html>', 'text/html'),
        make('/json?q=%3Cdemo-marker%3E', {'echo': '<demo-marker>'}),
        make('/oauth/token', {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh'}),
        make('/health', {'status': 'ok'}),
    ]


def run(output):
    output = Path(output)
    if output.exists(): raise ValueError('Use a new demo output directory')
    generate(fixture(), output / 'base')
    result = create_recommendations(output / 'base', output / 'recommendations', ['example.test'])
    print(json.dumps(result['summary'], ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    run(parser.parse_args().output)
