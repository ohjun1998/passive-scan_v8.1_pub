"""Academy mapping, conservative feature surfaces and unavailable capture boundaries."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_review import main
from examples.v88.demo import cases, make
from recon81.candidate_catalog import CATALOG, KINDS, BASE_KINDS
from recon81.candidate_rules import recommend, validate_refs
from recon81.candidate_review import make_packet, prompt_for
from recon81.candidate_report import create_recommendations, select_for_ai
from recon81.core import normalize_record, MASK, canonical
from recon81.reports import generate


class AcademyRulesTests(unittest.TestCase):
    def leads(self, record, kind):
        leads, clean, _ = recommend([record], ['example.test'])
        for c in leads: validate_refs(c, clean)
        return [c for c in leads if c['kind'] == kind]

    def test_catalog_maps_all_thirty_vulnerability_topics(self):
        topics = {'sql-injection', 'authentication', 'file-path-traversal', 'os-command-injection',
          'logic-flaws', 'information-disclosure', 'access-control', 'file-upload', 'race-conditions',
          'ssrf', 'xxe', 'nosql-injection', 'api-testing', 'web-cache-deception', 'cross-site-scripting',
          'csrf', 'cors', 'clickjacking', 'dom-based', 'websockets', 'deserialization', 'llm-attacks',
          'graphql', 'server-side-template-injection', 'web-cache-poisoning', 'host-header',
          'request-smuggling', 'oauth', 'jwt', 'prototype-pollution'}
        self.assertEqual(topics, {v['topic'] for v in CATALOG.values()})
        self.assertEqual(33, len(KINDS))
        self.assertTrue(BASE_KINDS <= set(KINDS))

    def test_each_added_type_has_anchored_synthetic_example_except_raw_transport(self):
        examples = cases()
        self.assertEqual(set(KINDS) - BASE_KINDS - {'request_smuggling'}, set(examples))
        for kind, record in examples.items():
            with self.subTest(kind=kind):
                leads = self.leads(record, kind)
                self.assertTrue(leads)
                self.assertFalse(leads[0]['confirmed'])
                self.assertFalse(leads[0]['reproduction_verified'])
                self.assertEqual(CATALOG[kind]['source_url'], leads[0]['source_url'])

    def test_cors_public_wildcard_and_same_origin_not_exploitable_read_signals(self):
        for origin, allowed in [('https://example.test', 'https://example.test'), ('https://client.example.test', '*')]:
            r = make('/public', 'public', headers={'Origin': origin}, response_headers={
                'Access-Control-Allow-Origin': allowed, 'Access-Control-Allow-Credentials': 'true'})
            self.assertEqual([], self.leads(r, 'cors'))
        self.assertEqual([], self.leads(make('/public', response_headers={'Access-Control-Allow-Origin': '*'}), 'cors'))

    def test_cors_boolean_is_preserved_but_unknown_secret_values_stay_masked(self):
        from recon81.core import sanitize_headers, get_header
        for value in ('true', 'false', ' true '):
            headers = sanitize_headers({'Access-Control-Allow-Credentials': value})
            self.assertEqual(value.strip().lower(), get_header(headers, 'access-control-allow-credentials'))
        for value in ('TRUE', 'synthetic-secret'):
            headers = sanitize_headers({'Access-Control-Allow-Credentials': value, 'Authorization': 'synthetic-secret'})
            self.assertEqual(MASK, get_header(headers, 'access-control-allow-credentials'))
        self.assertEqual(MASK, get_header(headers, 'authorization'))

    def test_reflected_credentialed_origin_is_unverified_trust_signal(self):
        r = make('/private', headers={'Origin': 'https://client.example.test'}, response_headers={
            'Access-Control-Allow-Origin': 'https://client.example.test', 'Access-Control-Allow-Credentials': 'true'})
        lead = self.leads(r, 'cors')[0]
        self.assertEqual('evidence_signal', lead['lead_class'])
        self.assertIn('정상 신뢰', lead['limitations'][0])

    def test_clickjacking_valid_policies_protect_but_report_only_and_default_do_not(self):
        html = '<html><button>Save</button></html>'
        for headers in ({'X-Frame-Options': 'DENY'}, {'X-Frame-Options': 'SAMEORIGIN'},
                        {'Content-Security-Policy': "frame-ancestors 'none'"},
                        {'Content-Security-Policy': "frame-ancestors 'self' https://trusted.example.test"}):
            self.assertEqual([], self.leads(make('/settings', html, mime='text/html', response_headers=headers), 'clickjacking'))
        for headers in ({'Content-Security-Policy-Report-Only': "frame-ancestors 'none'"},
                        {'Content-Security-Policy': "default-src 'none'"},
                        {'Content-Security-Policy': 'frame-ancestors *'},
                        {'Content-Security-Policy': "frame-ancestors 'unsafe-inline'"}):
            self.assertTrue(self.leads(make('/settings', html, mime='text/html', response_headers=headers), 'clickjacking'))
        self.assertEqual([], self.leads(make('/static', '<html>Read only</html>', mime='text/html'), 'clickjacking'))

    def test_csrf_requires_cookie_mutation_and_simple_request_and_is_only_surface(self):
        r = cases()['csrf']
        self.assertEqual('review_surface', self.leads(r, 'csrf')[0]['lead_class'])
        for headers in ({'Content-Type': 'application/x-www-form-urlencoded'},
                        {'Cookie': 'synthetic', 'Content-Type': 'application/json'},
                        {'Cookie': 'synthetic', 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': 'synthetic'}):
            self.assertEqual([], self.leads(make('/preferences', method='POST', body='language=ko', headers=headers), 'csrf'))
        self.assertEqual([], self.leads(make('/preferences', method='POST', body='csrf_token=synthetic&language=ko',
            headers={'Cookie': 'synthetic', 'Content-Type': 'application/x-www-form-urlencoded'}), 'csrf'))

    def test_path_input_without_returned_file_is_surface_and_blocked_is_not_signal(self):
        for path in ('/download?file=guide.pdf', '/download?file=..%2Fguide.pdf'):
            leads = self.leads(make(path), 'path_traversal')
            self.assertEqual('review_surface', leads[0]['lead_class'])
        self.assertEqual([], self.leads(make('/download?file=..%2Fguide.pdf', status=403), 'path_traversal'))

    def test_ssrf_url_without_correlated_error_is_surface_no_network_or_dns(self):
        r = make('/preview?url=https%3A%2F%2Fremote.example.test%2Fimage', 'ECONNREFUSED another.example.test')
        with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS permitted')):
            lead = self.leads(r, 'ssrf')[0]
        self.assertEqual('review_surface', lead['lead_class'])
        self.assertEqual([], self.leads(make('/preview?url=relative-file'), 'ssrf'))

    def test_xxe_xml_usage_is_surface_and_explicit_rejection_is_not_signal(self):
        normal = make('/parse', method='POST', body='<root/>', headers={'Content-Type': 'application/xml'})
        self.assertEqual('review_surface', self.leads(normal, 'xxe')[0]['lead_class'])
        blocked = make('/parse', 'SAXParseException: DOCTYPE is disallowed', 'POST', '<root/>', headers={'Content-Type': 'application/xml'}, status=400)
        self.assertEqual([], self.leads(blocked, 'xxe'))
        self.assertEqual([], self.leads(make('/text', 'SAXParseException: sample'), 'xxe'))

    def test_api_graphql_llm_jwt_oauth_and_upload_are_surfaces_not_bug_claims(self):
        for kind in ('api_testing', 'graphql', 'web_llm', 'jwt', 'oauth', 'file_upload', 'race_conditions', 'dom_based'):
            with self.subTest(kind=kind):
                lead = self.leads(cases()[kind], kind)[0]
                self.assertEqual('review_surface', lead['lead_class'])
                self.assertEqual('low', lead['priority'])

    def test_websocket_normal_upgrade_is_surface_and_requires_101(self):
        record = make('/socket', '', headers={'Upgrade': 'websocket', 'Origin': 'https://example.test'}, status=101)
        self.assertEqual('review_surface', self.leads(record, 'websockets')[0]['lead_class'])
        self.assertEqual([], self.leads(make('/socket', headers={'Upgrade': 'websocket'}, status=403), 'websockets'))

    def test_cache_hit_or_proxy_header_alone_never_proves_poisoning(self):
        for record in [make('/cached', response_headers={'X-Cache': 'HIT'}),
                       make('/plain', headers={'X-Forwarded-Host': 'other.example.test'}),
                       cases()['host_header']]:
            self.assertEqual([], self.leads(record, 'cache_poisoning'))
        self.assertEqual([], self.leads(make('/public/demo.css', {'title': 'public'}, mime='application/json',
            response_headers={'X-Cache': 'HIT'}), 'cache_deception'))

    def test_prototype_name_with_blocked_response_is_not_pollution(self):
        self.assertEqual([], self.leads(make('/merge', 'rejected', 'POST', '{"__proto__":{"x":true}}',
            headers={'Content-Type': 'application/json'}, status=400), 'prototype_pollution'))

    def test_normal_positive_quantity_is_not_business_logic_signal(self):
        leads = self.leads(make('/checkout', method='POST', body='{"quantity":1}', headers={'Content-Type': 'application/json'}), 'business_logic')
        self.assertEqual('review_surface', leads[0]['lead_class'])

    def test_masked_jwt_is_not_decoded_or_reconstructed(self):
        jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vIn0.synthetic'
        r = normalize_record('https://example.test/data', 'GET', headers={'Authorization': 'Bearer ' + jwt}, body=b'')
        leads, clean, _ = recommend([r], ['example.test'])
        self.assertEqual([], [c for c in leads if c['kind'] == 'jwt'])
        self.assertNotIn(jwt, canonical(clean))
        self.assertIn(MASK, canonical(clean))

    def test_noisy_surface_does_not_take_ai_slots_without_explicit_option(self):
        leads = recommend(list(cases().values()), ['example.test'])[0]
        selected = select_for_ai(leads, 100)
        self.assertTrue(selected)
        self.assertTrue(all(c['lead_class'] == 'evidence_signal' for c in selected))
        self.assertEqual(len(leads), len(select_for_ai(leads, 100, True)))
        prompt = prompt_for(make_packet(selected[:8]))
        self.assertIn('기능 점검 대상이며 결함 근거가 아닙니다', prompt)
        self.assertIn('원시 전송', prompt)


class AcademyReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_missing_evidence_is_reported_for_every_type_including_raw_framing(self):
        # Normalization removes framing; its absence must not be treated as a clean scan.
        record = make('/health', headers={'Content-Length': '0', 'Transfer-Encoding': 'chunked'})
        self.assertFalse(any(h['name'].lower() in ('content-length', 'transfer-encoding') for h in record['headers']))
        generate([record], self.root / 'source')
        r = create_recommendations(self.root / 'source', self.root / 'result', ['example.test'])
        self.assertEqual(33, len(r['type_coverage']))
        smuggling = next(c for c in r['type_coverage'] if c['kind'] == 'request_smuggling')
        self.assertEqual('additional_capture_required', smuggling['status'])
        self.assertEqual(0, r['summary']['candidates'])
        self.assertTrue(r['capture_constraints'])
        html = (self.root / 'result/index.html').read_text()
        self.assertIn('추가 수집 필요·미평가', html)
        self.assertIn('안전 판정 아님', html)
        self.assertIn('leadclass', html)

    def test_legacy_masked_cors_stays_unknown(self):
        record = cases()['cors']
        for h in record['response']['headers']:
            if h['name'].lower() == 'access-control-allow-credentials': h['value'] = MASK
        generate([record], self.root / 'legacy')
        r = create_recommendations(self.root / 'legacy', self.root / 'result', ['example.test'])
        cors = next(c for c in r['type_coverage'] if c['kind'] == 'cors')
        self.assertEqual('additional_capture_required', cors['status'])
        self.assertIn('masked', cors['capture_limitation'])
        self.assertEqual(0, r['summary']['signal_candidates'])

    def test_surface_only_ai_default_zero_calls_and_cli_opt_in_remains_bounded(self):
        generate([cases()['graphql'], cases()['jwt'], cases()['web_llm']], self.root / 'source')
        with patch('recon81.candidate_report.execute_candidates') as model:
            r = create_recommendations(self.root / 'source', self.root / 'default', ['example.test'], ai=True)
            model.assert_not_called()
        self.assertEqual(3, r['summary']['review_surfaces'])
        self.assertEqual(3, r['summary']['ai_excluded_surface_count'])
        def fake(packet, *args):
            self.assertEqual(2, len(packet['candidates']))
            return {'packet_id': packet['packet_id'], 'reviews': [{'candidate_id': c['candidate_id'], 'disposition': 'needs_context',
                'priority': 'low', 'reason': '기능 점검 대상입니다.', 'next_check': '정책을 확인하세요.'} for c in packet['candidates']]}, {
                'status': 'completed', 'provider': 'codex_chatgpt_login', 'candidate_validation': 'verified',
                'model_execution_verified': True, 'completion_events_verified': True}
        with patch('recon81.candidate_report.execute_candidates', side_effect=fake):
            with patch('sys.stdout', new_callable=io.StringIO):
                status = main(['recommend', '--report', str(self.root / 'source'), '--scope', 'example.test',
                    '--output', str(self.root / 'explicit'), '--ai', '--ai-include-surfaces', '--ai-limit', '2'])
        self.assertEqual(0, status)
        r = json.loads((self.root / 'explicit/recommendations.json').read_text())
        self.assertEqual(2, r['summary']['ai_reviewed_candidates'])
        self.assertTrue(all(c['lead_class'] == 'review_surface' for c in r['candidates']))


if __name__ == '__main__': unittest.main()
