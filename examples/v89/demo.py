#!/usr/bin/env python3
"""Saved-only context, reuse and human-feedback demo. --ai is explicitly optional."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from recon81.core import normalize_record
from recon81.context import attach_context
from recon81.reports import generate
from recon81.candidate_report import create_recommendations


def make(path, response, method='GET', body=b'', scenario='demo', actor='customer', access='unknown'):
    record = normalize_record('https://example.test' + path, method, body=body,
        headers={'Content-Type': 'application/json'} if body else {}, response={'status': 200,
            'headers': {'Content-Type': 'application/json'}, 'body': json.dumps(response)}, source='synthetic_v89_demo')
    return attach_context(record, {**({'actor': actor} if actor else {}), 'capture_id': 'saved-demo', 'scenario': scenario, 'expected_access': access})


def fixture():
    normal = make('/quote', {'total': 100, 'approvalRequired': True}, 'POST', '{"plan":"standard"}', 'Customer quote: unit price changes require staff approval')
    suspect = make('/quote', {'total': 1, 'approvalRequired': False}, 'POST',
        '{"plan":"standard","unitPriceOverride":1,"overrideApproval":true}', 'Customer quote: unit price changes require staff approval')
    upload = make('/attachments', {'fileId': 'F-89'}, 'POST', '{"name":"demo.txt"}', 'document-flow')
    download = make('/attachments/download?fileId=F-89', {'content': 'synthetic document'}, scenario='document-flow')
    # One deterministic lead; all other examples remain available for discovery.
    private = make('/orders/89', {'ownerId': 'other', 'total': 25}, scenario='order-access', access='deny')
    owner = make('/orders/89', {'ownerId': 'other', 'total': 25}, scenario='order-access', actor='other', access='allow')
    return [normal, suspect, upload, download, private, owner, make('/health', {'ok': True}, actor=None)]


def run(output, ai=False):
    output = Path(output)
    if output.exists(): raise ValueError('Use a new output directory')
    generate(fixture(), output / 'base')
    r = create_recommendations(output / 'base', output / 'recommendations', ['example.test'], ai=ai,
        discover=ai, ai_limit=8, discovery_limit=4, cache_path=output / 'reuse.sqlite3' if ai else None)
    print(json.dumps(r['summary'], ensure_ascii=False))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--output', required=True); p.add_argument('--ai', action='store_true')
    a = p.parse_args(); run(a.output, a.ai)
