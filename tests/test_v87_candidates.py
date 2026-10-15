"""Mixed-type leads, evidence anchoring, bounded model selection and fail-closed outputs."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_review import main
from examples.v87.demo import fixture, make
from recon81.candidate_catalog import BASE_KINDS as KINDS
from recon81.candidate_rules import recommend, validate_refs, clean_record
from recon81.candidate_review import make_packet, validate_decisions, prompt_for, execute_candidates
from recon81.candidate_report import create_recommendations, select_for_ai
from recon81.codex_review import ReviewFailure
from recon81.core import MASK, canonical, normalize_record
from recon81.reports import generate


def decisions(packet):
    return {'packet_id': packet['packet_id'], 'reviews': [
        {'candidate_id': c['candidate_id'], 'disposition': 'needs_context', 'priority': 'low',
         'reason': '정책·실행 맥락을 추가로 확인해야 합니다.', 'next_check': '해당 필드의 공개 정책을 확인하세요.'}
        for c in packet['candidates']]}


def verified(packet, *args):
    return decisions(packet), {'provider': 'codex_chatgpt_login', 'status': 'completed',
        'model_execution_verified': True, 'completion_events_verified': True, 'candidate_validation': 'verified'}


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.records = fixture()
        self.leads, self.clean, self.outside = recommend(self.records, ['example.test'])

    def test_all_six_types_and_only_six_synthetic_subjects(self):
        self.assertEqual(set(KINDS), {c['kind'] for c in self.leads})
        self.assertEqual(6, len(self.leads))
        self.assertEqual(0, self.outside)
        for c in self.leads:
            validate_refs(c, self.clean)
            self.assertFalse(c['confirmed'])
            self.assertFalse(c['reproduction_verified'])

    def test_normal_owner_is_support_not_subject(self):
        lead = next(c for c in self.leads if c['kind'] == 'idor')
        self.assertEqual([self.records[0]['observation_id']], lead['subject_ids'])
        self.assertEqual([self.records[1]['observation_id']], lead['support_ids'])
        self.assertFalse(any(self.records[1]['observation_id'] in c['subject_ids'] for c in self.leads))

    def test_escaped_text_and_json_reflections_and_oauth_are_not_leads(self):
        subjects = {oid for c in self.leads for oid in c['subject_ids']}
        for record in self.records[7:]:
            self.assertNotIn(record['observation_id'], subjects)

    def test_source_and_sink_is_only_low_strength_without_flow_claim(self):
        record = make('/client.js', 'const a=location.hash; element.innerHTML="static";', 'text/javascript')
        leads, _, _ = recommend([record], ['example.test'])
        self.assertEqual(1, len(leads))
        self.assertEqual('low', leads[0]['signal_strength'])
        self.assertIn('추적하지', leads[0]['limitations'][0])

    def test_full_saved_body_beyond_old_prefix_is_examined(self):
        record = make('/large', {'padding': 'x' * 12000, 'email': 'demo@example.test'})
        leads, _, _ = recommend([record], ['example.test'])
        self.assertEqual('sensitive_data', leads[0]['kind'])
        self.assertEqual('/email', leads[0]['evidence'][0]['pointer'])

    def test_old_imported_secret_is_redacted_in_all_outputs(self):
        secret = 'ghp_' + 'A' * 32
        record = make('/old.js', 'const data = "placeholder";', 'text/javascript')
        record['response']['body']['text'] = 'const apiKey = "' + secret + '";'
        leads, clean, _ = recommend([record], ['example.test'])
        self.assertEqual('credential_exposure', leads[0]['kind'])
        self.assertNotIn(secret, canonical([leads, clean, make_packet(leads)]))
        self.assertIn(MASK, canonical(clean))

    def test_normal_request_authorization_and_cookie_are_not_exposure(self):
        record = normalize_record('https://example.test/health', 'GET', body=b'', headers={
            'Authorization': 'Bearer synthetic-only', 'Cookie': 'session=synthetic'},
            response={'status': 200, 'headers': {'Content-Type': 'application/json'}, 'body': '{"ok":true}'})
        self.assertEqual([], recommend([record], ['example.test'])[0])

    def test_scope_and_url_only_secret_lead(self):
        record = normalize_record('https://example.test/download?api_key=synthetic', 'UNKNOWN', observed=False)
        leads, clean, outside = recommend([record, make('/health', {})], ['other.test'])
        self.assertEqual(([], {}, 2), (leads, clean, outside))
        leads, _, _ = recommend([record], ['example.test'])
        self.assertEqual('credential_parameter_in_url', leads[0]['rule'])

    def test_late_query_and_slash_parameter_have_exact_input_evidence(self):
        record = make('/reflect?padding=' + 'a' * 300 + '&%2Fq=%3Cdemo-marker%3E',
                      '<html><demo-marker></html>', 'text/html')
        leads, clean, _ = recommend([record], ['example.test'])
        self.assertEqual('xss', leads[0]['kind'])
        self.assertGreater(leads[0]['evidence'][0]['start'], 300)
        self.assertIn('%2Fq=', leads[0]['evidence'][0]['excerpt'])
        validate_refs(leads[0], clean)

    def test_tampered_or_control_only_references_fail(self):
        lead = copy.deepcopy(self.leads[0])
        lead['evidence'][0]['excerpt'] += 'invented'
        with self.assertRaises(ValueError): validate_refs(lead, self.clean)
        lead = copy.deepcopy(next(c for c in self.leads if c['support_ids']))
        lead['evidence'] = [r for r in lead['evidence'] if r['observation_id'] in lead['support_ids']]
        with self.assertRaises(ValueError): validate_refs(lead, self.clean)

    def test_selection_preserves_types_before_extra_auth_leads(self):
        auth = next(c for c in self.leads if c['kind'] == 'idor')
        copies = [dict(auth, candidate_id=format(i, '064x')) for i in range(30)]
        selected = select_for_ai(copies + self.leads, 6)
        self.assertEqual(set(KINDS), {c['kind'] for c in selected})


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.leads = recommend(fixture(), ['example.test'])[0]
        self.packet = make_packet(self.leads)

    def test_prompt_is_untrusted_and_candidate_only(self):
        instructions, payload = prompt_for(self.packet).split('UNTRUSTED_CANDIDATES_JSON\n')
        self.assertEqual(self.packet, json.loads(payload))
        for phrase in ('신뢰할 수 없는', 'support_ids', '취약점 확정이 아닙니다', '보고서 초안'):
            self.assertIn(phrase, instructions)

    def test_exact_complete_ids_packet_and_no_extra_actions(self):
        valid = decisions(self.packet)
        self.assertEqual(valid, validate_decisions(valid, self.packet))
        invalids = []
        value = copy.deepcopy(valid); value['reviews'].pop(); invalids.append(value)
        value = copy.deepcopy(valid); value['reviews'][0]['candidate_id'] = 'f' * 64; invalids.append(value)
        value = copy.deepcopy(valid); value['reviews'][0] = value['reviews'][1]; invalids.append(value)
        value = copy.deepcopy(valid); value['packet_id'] = 'f' * 64; invalids.append(value)
        value = copy.deepcopy(valid); value['reviews'][0]['confirmed'] = True; invalids.append(value)
        for value in invalids:
            with self.assertRaises(ValueError): validate_decisions(value, self.packet)

    def test_provider_schema_binds_ids_and_uses_common_guarded_transport(self):
        def transport(prompt, schema, validator, *args, **kwargs):
            self.assertEqual([self.packet['packet_id']], schema['properties']['packet_id']['enum'])
            self.assertEqual({c['candidate_id'] for c in self.leads},
                set(schema['properties']['reviews']['items']['properties']['candidate_id']['enum']))
            return validator(decisions(self.packet)), {}
        with patch('recon81.codex_review._execute_json', side_effect=transport):
            _, receipt = execute_candidates(self.packet)
            self.assertEqual('verified', receipt['candidate_validation'])
        corrupt = copy.deepcopy(self.packet); corrupt['candidates'][0]['reason'] = 'changed'
        with self.assertRaises(ValueError): execute_candidates(corrupt)


class ReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.source = self.root / 'source'
        generate(fixture(), self.source)

    def create(self, name='output', **kwargs):
        return create_recommendations(self.source, self.root / name, ['example.test'], **kwargs)

    def test_default_is_offline_with_explicit_body_and_ai_coverage(self):
        with patch('recon81.candidate_report.execute_candidates') as model:
            report = self.create()
            model.assert_not_called()
        self.assertEqual(12, report['summary']['rule_processed_records'])
        self.assertEqual(0, report['summary']['ai_reviewed_candidates'])
        self.assertEqual(0, report['summary']['target_requests_sent'])
        self.assertTrue(report['source_manifest_verified'])
        self.assertTrue((self.root / 'output/index.html').is_file())
        self.assertTrue((self.root / 'output/manifest.json').is_file())
        self.assertFalse((self.root / 'output/model-inputs').exists())

    def test_short_ai_decisions_cannot_change_subjects_or_evidence(self):
        before = self.create('before')['candidates']
        with patch('recon81.candidate_report.execute_candidates', side_effect=verified):
            report = self.create(ai=True, batch_size=3, workers=2)
        self.assertEqual(2, report['summary']['model_calls'])
        self.assertEqual(6, report['summary']['ai_reviewed_candidates'])
        self.assertEqual(set(KINDS), set(report['summary']['ai_reviewed_by_kind']))
        for c in report['candidates']:
            original = next(x for x in before if x['candidate_id'] == c['candidate_id'])
            for key in ('subject_ids', 'support_ids', 'evidence', 'kind'):
                self.assertEqual(original[key], c[key])
        control = next(r for r in report['records'] if r['observation_id'] == fixture()[1]['observation_id'])
        self.assertFalse(control['ai_subject_reviewed'])

    def test_failed_model_keeps_candidates_and_cli_returns_partial_failure(self):
        with patch('recon81.candidate_report.execute_candidates', side_effect=ReviewFailure('FIXTURE_FAILURE', 'candidate_validation')):
            with patch('sys.stdout', new_callable=io.StringIO):
                status = main(['recommend', '--report', str(self.source), '--output', str(self.root / 'failed'),
                               '--scope', 'example.test', '--ai'])
        self.assertEqual(3, status)
        report = json.loads((self.root / 'failed/recommendations.json').read_text())
        self.assertEqual(6, report['summary']['ai_not_reviewed_candidates'])
        self.assertEqual(1, report['summary']['ai_failed_packets'])
        self.assertTrue(all(c['state'] == 'rule_candidate' for c in report['candidates']))

    def test_unverified_execution_and_invalid_decision_rejected(self):
        for name, adapter in [('unverified', lambda p, *a: (decisions(p), {})),
                              ('invalid', lambda p, *a: ({'packet_id': p['packet_id'], 'reviews': []}, {}))]:
            with patch('recon81.candidate_report.execute_candidates', side_effect=adapter):
                report = self.create(name, ai=True)
            self.assertEqual(0, report['summary']['ai_reviewed_candidates'])
            self.assertEqual(1, report['summary']['ai_failed_packets'])

    def test_html_escapes_evidence_and_existing_output_refused_before_model(self):
        self.create()
        html = (self.root / 'output/index.html').read_text()
        self.assertIn('&lt;demo-marker&gt;', html)
        self.assertNotIn('<demo-marker>', html)
        with patch('recon81.candidate_report.execute_candidates') as model:
            with self.assertRaises(ValueError): self.create(ai=True)
            model.assert_not_called()

    def test_budget_and_packet_size_and_oversized_are_explicit(self):
        for options in ({'ai_limit': 0}, {'workers': 5}, {'batch_size': 13}):
            with self.assertRaises(ValueError): self.create(**options)
        with patch('recon81.candidate_report.execute_candidates', side_effect=verified):
            report = self.create(ai=True, ai_limit=3, batch_size=2)
        self.assertEqual(3, report['summary']['ai_reviewed_candidates'])
        self.assertEqual(3, report['summary']['ai_not_reviewed_candidates'])
        for file in (self.root / 'output/model-inputs').glob('*.json'):
            self.assertLessEqual(len(canonical(json.loads(file.read_text())).encode()), 24576)

    def test_oversized_context_stays_manual_without_model_call(self):
        from recon81.candidate_rules import recommend as real_recommend
        def oversized(*args):
            leads, clean, outside = real_recommend(*args)
            for lead in leads: lead['authority'] = {'provenance': 'x' * 25000}
            return leads, clean, outside
        with patch('recon81.candidate_report.recommend', side_effect=oversized):
            with patch('recon81.candidate_report.execute_candidates') as model:
                report = self.create(ai=True)
                model.assert_not_called()
        self.assertEqual(6, report['summary']['ai_oversized_candidates'])
        self.assertEqual(6, report['summary']['ai_not_reviewed_candidates'])


if __name__ == '__main__': unittest.main()
