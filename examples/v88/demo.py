#!/usr/bin/env python3
"""Synthetic Academy topic mapping. Feature surfaces are not vulnerability findings."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from recon81.core import normalize_record
from recon81.reports import generate
from recon81.candidate_report import create_recommendations
from examples.v87.demo import fixture as base_fixture


def make(path, response='ok', method='GET', body=b'', mime='text/plain', headers=None, response_headers=None, status=200):
    rh = dict({'Content-Type': mime}, **(response_headers or {}))
    return normalize_record('https://example.test' + path, method, headers=headers, body=body, response={
        'status': status, 'headers': rh, 'body': json.dumps(response) if isinstance(response, dict) else response},
        include_text=True, source='synthetic_v88_demo')


def cases():
    """One focused case per added type, plus cross-topic evidence when appropriate."""
    return {
        'authentication': normalize_record('http://example.test/login', 'POST', headers={'Content-Type': 'application/json'},
            body='{"password":"synthetic","username":"demo"}', response={'status': 200, 'body': 'saved'}, source='synthetic_v88_demo'),
        'path_traversal': make('/download?file=..%2F..%2Fdemo', 'root:x:0:0:synthetic:/demo:/bin/false'),
        'command_injection': make('/convert?name=sample', '/bin/sh: sample: not found'),
        'business_logic': make('/checkout', {'result': 'accepted'}, 'POST', '{"quantity":-1}', headers={'Content-Type': 'application/json'}, mime='application/json'),
        'information_disclosure': make('/debug', 'Traceback (most recent call last):\n  File "/srv/demo.py", line 2'),
        'file_upload': make('/upload', 'saved', 'POST', '--demo\r\nContent-Disposition: form-data; name="file"; filename="demo.txt"\r\nContent-Type: text/plain\r\n\r\nsynthetic\r\n--demo--\r\n', headers={'Content-Type': 'multipart/form-data; boundary=demo'}),
        'race_conditions': make('/redeem', {'ok': True}, 'POST', '{"coupon":"demo"}', headers={'Content-Type': 'application/json'}, mime='application/json'),
        'ssrf': make('/preview?url=http%3A%2F%2F127.0.0.1%3A8080%2Fdemo', 'ECONNREFUSED 127.0.0.1:8080'),
        'xxe': make('/parse', 'SAXParseException: synthetic parse failure', 'POST', '<root><item>demo</item></root>', headers={'Content-Type': 'application/xml'}),
        'nosql_injection': make('/lookup', 'MongoServerError: unknown top level operator: $demo'),
        'api_testing': make('/api/v1/status', {'ok': True}, mime='application/json'),
        'cache_deception': make('/profile/demo.css', {'email': 'demo@example.test'}, mime='application/json', headers={'Cookie': 'session=synthetic'}, response_headers={'X-Cache': 'HIT'}),
        'csrf': make('/preferences', 'saved', 'POST', 'language=ko', headers={'Cookie': 'session=synthetic', 'Content-Type': 'application/x-www-form-urlencoded'}),
        'cors': make('/data', '{"private_demo":true}', headers={'Origin': 'null'}, response_headers={'Access-Control-Allow-Origin': 'null', 'Access-Control-Allow-Credentials': 'true'}),
        'clickjacking': make('/settings', '<html><form><button>Demo</button></form></html>', mime='text/html'),
        'dom_based': make('/client.js', 'const source=location.hash; element.innerHTML="static";', mime='text/javascript'),
        'websockets': make('/socket', '', headers={'Upgrade': 'websocket', 'Origin': 'null', 'Cookie': 'session=synthetic'}, status=101),
        'deserialization': make('/restore', 'java.io.StreamCorruptedException: synthetic header'),
        'web_llm': make('/assistant', {'choices': []}, 'POST', '{"model":"demo","messages":[{"role":"user","content":"synthetic"}]}', headers={'Content-Type': 'application/json'}, mime='application/json'),
        'graphql': make('/graphql', {'data': {'version': 'demo'}}, 'POST', '{"query":"query { version }"}', headers={'Content-Type': 'application/json'}, mime='application/json'),
        'ssti': make('/render', 'jinja2.exceptions.TemplateSyntaxError: synthetic failure'),
        'cache_poisoning': make('/cached-link', 'https://other.example.test/demo', headers={'X-Forwarded-Host': 'other.example.test'}, response_headers={'X-Cache': 'HIT'}),
        'host_header': make('/host-link', 'https://other.example.test/demo', headers={'X-Forwarded-Host': 'other.example.test'}),
        'oauth': make('/authorize?client_id=demo&response_type=code&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback'),
        'jwt': make('/.well-known/jwks.json', {'keys': [{'kty': 'RSA', 'kid': 'demo', 'alg': 'RS256', 'n': 'public-demo', 'e': 'AQAB'}]}, mime='application/json'),
        'prototype_pollution': make('/merge', {'ok': True}, 'POST', '{"__proto__":{"demo":true}}', headers={'Content-Type': 'application/json'}, mime='application/json'),
    }


def run(output):
    output = Path(output)
    if output.exists(): raise ValueError('Use a new demo output directory')
    records = base_fixture() + list(cases().values())
    generate(records, output / 'base')
    report = create_recommendations(output / 'base', output / 'recommendations', ['example.test'])
    print(json.dumps(report['summary'], ensure_ascii=False))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--output', required=True)
    run(p.parse_args().output)
