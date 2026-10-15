#!/usr/bin/env python3
"""Reproduce the supplied Community Security Lab 3.4 fixture on loopback only."""
import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon81.core import normalize_record, private_write
from recon81.context import attach_context
from recon81.reports import generate

ACTORS = {'alice': (1, 'USER'), 'bob': (2, 'USER'), 'admin': (3, 'ADMIN'), 'moderator': (4, 'MODERATOR')}
CASES = [
    {'name': 'orders', 'path': '/api/{mode}/orders/102', 'allowed': ['bob']},
    {'name': 'posts', 'path': '/api/community/{mode}/posts/102', 'allowed': ['bob', 'admin']},
    {'name': 'messages', 'path': '/api/community/{mode}/messages/202', 'allowed': ['bob', 'admin']},
    {'name': 'files', 'path': '/api/community/{mode}/files/bob-private-file', 'allowed': ['bob', 'admin']},
    {'name': 'admin_users', 'path': '/api/community/{mode}/admin/users?role=ADMIN', 'allowed': ['admin']},
]


def local_target(value):
    p = urllib.parse.urlsplit(value)
    if p.scheme != 'http' or p.username or p.password or p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('LOOPBACK_LAB_REQUIRED')
    try:
        valid = ipaddress.ip_address(p.hostname).is_loopback and 1 <= (p.port or 80) <= 65535
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError('LOOPBACK_LAB_REQUIRED')
    return value.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('LAB_REDIRECT_BLOCKED')


def private_data(case, text):
    if case == 'files':
        return 'BOB_PRIVATE_ATTACHMENT: project notes' in text
    try:
        value = json.loads(text)
        if case == 'orders':
            return value.get('ID') == 102 and value.get('OWNER_ID') == 2 and 'PRODUCT' in value
        if case == 'posts':
            return value.get('ID') == 102 and value.get('OWNER_ID') == 2 and value.get('VISIBILITY') == 'PRIVATE' and 'BOB_PRIVATE_NOTE' in value.get('BODY', '')
        if case == 'messages':
            return value.get('ID') == 202 and value.get('SENDER_ID') == 2 and value.get('RECEIVER_ID') == 3 and 'BOB_TO_ADMIN_PRIVATE_MESSAGE' in value.get('BODY', '')
        if case == 'admin_users':
            return isinstance(value, list) and any(v.get('ID') == 2 and v.get('EMAIL') == 'bob@lab.invalid' for v in value if isinstance(v, dict))
    except (ValueError, TypeError, AttributeError):
        pass
    return False


def classify(case, actor, status, text):
    allowed = actor in case['allowed']
    data = private_data(case['name'], text)
    return {'expected_access': 'allow' if allowed else 'deny', 'private_data_observed': data,
            'unauthorized_data_returned': not allowed and 200 <= status < 300 and data,
            'policy_match': (200 <= status < 300 and data) if allowed else status in (401, 403, 404) and not data}


class Capture:
    def __init__(self, target, output, password):
        self.target = local_target(target)
        self.output = Path(output)
        if self.output.exists() or self.output.is_symlink():
            raise ValueError('NEW_OUTPUT_REQUIRED')
        if len(password) < 8:
            raise ValueError('LAB_PASSWORD_REQUIRED')
        self.output.mkdir(parents=True, mode=0o700)
        self.password = password
        self.records = []
        self.started = time.monotonic()
        self.capture_id = 'local-reproduction-' + uuid.uuid4().hex
        self.clients = {name: urllib.request.build_opener(urllib.request.ProxyHandler({}),
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
                        for name in ['anonymous', *ACTORS]}

    def request(self, actor, path, scenario, expected='unknown', form=None):
        if len(self.records) >= 64 or time.monotonic() - self.started > 60:
            raise ValueError('LAB_BUDGET_EXCEEDED')
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('INVALID_LAB_PATH')
        body = urllib.parse.urlencode(form).encode() if form else None
        req = urllib.request.Request(self.target + path, data=body,
            headers={'Accept': 'application/json', **({'Content-Type': 'application/x-www-form-urlencoded'} if form else {})})
        try:
            response = self.clients[actor].open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('LAB_BODY_LIMIT')
            text = raw.decode('utf-8', errors='replace')
            status = response.code
            record = attach_context(normalize_record(self.target + path, 'POST' if form else 'GET',
                headers=dict(req.header_items()), body=body,
                response={'status': status, 'headers': list(response.headers.items()), 'body': text},
                source='community_lab_3.4_reproduction', include_text=True),
                {'actor': actor, 'capture_id': self.capture_id, 'expected_access': expected, 'scenario': scenario})
        encoded = json.dumps(record, ensure_ascii=False)
        if self.password in encoded:
            raise ValueError('CREDENTIAL_REDACTION_FAILED')
        self.records.append(record)
        private_write(self.output / 'capture.jsonl', ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in self.records))
        return status, text, {'observation_id': record['observation_id'], 'status': status,
                             'response_sha256': hashlib.sha256(raw).hexdigest(), 'response_bytes': len(raw)}


def reproduce(target, output, password):
    capture = Capture(target, output, password)
    result = {'fixture': 'Community Security Lab 3.4.0', 'target': capture.target,
              'status': 'failed', 'identities': [], 'samples': [], 'model_execution_verified': False,
              'human_confirmation_required': True, 'policy_provenance': 'Supplied lab source, seed data and test-policy.json',
              'notice': 'Fresh local fixture reproduction only; no automatic AI review or operational service confirmation.'}
    try:
        status, text, _ = capture.request('anonymous', '/health', 'training fixture identity', 'allow')
        if status != 200 or json.loads(text).get('trainingOnly') is not True:
            raise ValueError('TRAINING_FIXTURE_REQUIRED')
        for actor, (uid, role) in ACTORS.items():
            status, _, _ = capture.request(actor, '/api/auth/login', 'lab login', 'allow', {'username': actor, 'password': password})
            if status != 200:
                raise ValueError('LAB_LOGIN_FAILED')
            status, text, receipt = capture.request(actor, '/api/auth/me', 'same CookieJar identity', 'allow')
            user = json.loads(text).get('user', {})
            if status != 200 or user.get('ID') != uid or user.get('ROLE') != role:
                raise ValueError('LAB_IDENTITY_MISMATCH')
            result['identities'].append(dict(receipt, actor=actor, user_id=uid, role=role))
        for case in CASES:
            for mode in ('vuln', 'fixed'):
                for actor in ['anonymous', *ACTORS]:
                    expected = 'allow' if actor in case['allowed'] else 'deny'
                    status, text, receipt = capture.request(actor, case['path'].format(mode=mode), case['name'] + ' ' + mode, expected)
                    result['samples'].append(dict(receipt, actor=actor, mode=mode, case=case['name'], **classify(case, actor, status, text)))
        error_rows = []
        for mode in ('vuln', 'fixed'):
            status, text, receipt = capture.request('alice', '/api/community/' + mode + '/search?q=%27', 'error disclosure ' + mode, 'allow')
            error_rows.append(dict(receipt, mode=mode, internal_sql='SELECT * FROM community_posts' in text,
                                   internal_exception='org.springframework.jdbc' in text))
        result['error_checks'] = error_rows
        samples = result['samples']
        fixed = [r for r in samples if r['mode'] == 'fixed']
        exposed = [r for r in samples if r['unauthorized_data_returned']]
        groups = sorted({r['case'] for r in exposed})
        result['summary'] = {'requests_sent': len(capture.records), 'identity_checks': len(result['identities']),
            'authorization_samples': len(samples), 'unauthorized_data_samples': len(exposed), 'resource_groups': groups,
            'fixed_policy_matches': sum(r['policy_match'] for r in fixed), 'fixed_samples': len(fixed),
            'error_disclosure_reproduced': error_rows[0]['status'] == 500 and error_rows[0]['internal_sql'] and error_rows[0]['internal_exception'],
            'fixed_error_control_passed': error_rows[1]['status'] == 200 and not error_rows[1]['internal_sql'] and not error_rows[1]['internal_exception']}
        summary = result['summary']
        passed = len(samples) == 50 and len(exposed) == 13 and len(groups) == 5 and len(fixed) == 25 and all(r['policy_match'] for r in fixed)
        passed = passed and summary['error_disclosure_reproduced'] and summary['fixed_error_control_passed']
        result.update(status='passed' if passed else 'failed', local_reproduction_verified=bool(passed),
                      local_cookiejar_identity_checked=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result.update(error_code=type(error).__name__, local_reproduction_verified=False)
    finally:
        result['requests_sent'] = len(capture.records)
        private_write(capture.output / 'reproduction.json', json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        if capture.records:
            generate(capture.records, capture.output / 'base-report', xlsx=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='http://127.0.0.1:18090')
    parser.add_argument('--output', required=True)
    parser.add_argument('--password-env', default='PASSIVE_LAB_PASSWORD')
    args = parser.parse_args()
    try:
        result = reproduce(args.target, args.output, os.environ.get(args.password_env, ''))
        print(json.dumps({'status': result['status'], 'summary': result.get('summary'), 'requests_sent': result['requests_sent']}))
        return 0 if result['status'] == 'passed' else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('Local reproduction failed: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
