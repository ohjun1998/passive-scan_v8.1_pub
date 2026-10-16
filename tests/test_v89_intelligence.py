"""Saved-only context, historical reuse, discovery anchors and exact-evidence human decisions."""
import copy
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_review import main
from examples.v89.demo import fixture, make
from recon81.candidate_rules import recommend, validate_refs
from recon81.candidate_context import EvidenceContext
from recon81.candidate_review import make_packet, validate_decisions, prompt_for as review_prompt
from recon81.candidate_discovery import build_tasks, validate, hypotheses, execute_discovery, prompt_for as discovery_prompt
from recon81.candidate_report import create_recommendations
from recon81.candidate_cache import runtime_fingerprint
from recon81.candidate_feedback import save_feedback, read_feedback, apply_feedback
from recon81.core import digest, canonical
from recon81.reports import generate


def reviewed(packet, *args):
    return {'packet_id': packet['packet_id'], 'reviews': [{'candidate_id': c['candidate_id'], 'disposition': 'needs_context',
        'priority': 'low', 'reason': '저장 자료의 후속 점검 후보입니다.', 'next_check': '실제 정책을 확인하세요.'} for c in packet['candidates']]}, {
        'provider': 'codex_chatgpt_login', 'status': 'completed', 'candidate_validation': 'verified',
        'completion_events_verified': True, 'model_execution_verified': True, 'tools_disabled': True,
        'requested_model': 'gpt-6.1-sol', 'requested_reasoning_effort': 'medium', 'prompt_sha256': digest(review_prompt(packet))}


def result_for(task, findings=False):
    choices = [e for e in task['evidence'] if e['observation_id'] in task['eligible_subject_ids'] and e['location'] != 'url']
    own = next((e for e in choices if 'unitPriceOverride' in str(e)), choices[0])
    return {'packet_id': task['packet_id'], 'findings': [{'kind': 'business_logic', 'subject_ids': [own['observation_id']], 'priority': 'low',
        'reason': '승인과 가격 입력의 정책 관계를 검토해야 합니다.', 'next_check': '실제 직원 승인 정책과 상태를 확인하세요.',
        'evidence_ids': [own['evidence_id']]}] if findings else []}


def discovered(task, *args):
    return result_for(task, True), {'provider': 'codex_chatgpt_login', 'status': 'completed', 'discovery_validation': 'verified',
        'completion_events_verified': True, 'model_execution_verified': True, 'tools_disabled': True,
        'requested_model': 'gpt-6.1-sol', 'requested_reasoning_effort': 'medium', 'prompt_sha256': digest(discovery_prompt(task))}


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.records = fixture()
        self.candidates, self.clean, _ = recommend(self.records, ['example.test'])
        self.context = EvidenceContext(self.clean)

    def test_normal_controls_remain_separate_and_local_context_is_exact(self):
        self.context.attach(self.candidates)
        c = self.candidates[0]
        self.assertEqual([self.records[4]['observation_id']], c['subject_ids'])
        self.assertEqual([self.records[5]['observation_id']], c['support_ids'])
        self.assertEqual(2, len(c['evidence_bundle']['records']))
        validate_refs(c, self.clean)
        self.assertTrue(c['evidence_digest'])
        self.assertIn('evidence_bundle', make_packet([c])['candidates'][0])

    def test_added_input_field_is_a_variant_and_response_difference_has_pointers(self):
        oid = self.records[1]['observation_id']
        bundle = self.context.bundle([oid])
        self.assertIn(self.records[0]['observation_id'], {r['observation_id'] for r in bundle['records']})
        self.assertTrue(any(r['kind'] == 'saved_request_variant' for r in bundle['relations']))
        self.assertTrue(any('/total' in d['changed_fields'] for d in bundle['response_differences']))
        self.assertTrue(any(r['pointer'] == '/approvalRequired' for r in bundle['evidence']))

    def test_value_flow_is_inferred_and_never_crosses_actor_or_scope(self):
        upload, download = self.records[2:4]
        bundle = self.context.bundle([download['observation_id']])
        self.assertIn(upload['observation_id'], {r['observation_id'] for r in bundle['records']})
        self.assertTrue(any(r['kind'] == 'inferred_value_flow' for r in bundle['relations']))
        bad = {'flows': [{'links': [{'from_id': upload['observation_id'], 'to_id': self.records[5]['observation_id'],
            'response_field': '$.fileId', 'request_field': 'query.fileId'}]}]}
        other = EvidenceContext(self.clean, bad)
        self.assertEqual([], other.edges.get(upload['observation_id'], []))

    def test_full_late_body_and_policy_changes_invalidate_context_identity(self):
        oid = self.records[1]['observation_id']; before = self.context.bundle([oid])['evidence_digest']
        for change in ('body', 'policy'):
            records = copy.deepcopy(self.clean)
            if change == 'body': records[oid]['response']['body']['text'] = '{"total":1,"padding":"' + 'x' * 9000 + '","late":true}'
            else: records[oid]['authority'] = {'policy': {'expected_access': 'deny', 'provenance': 'changed'}}
            self.assertNotEqual(before, EvidenceContext(records).bundle([oid])['evidence_digest'])

    def test_false_saved_flow_links_are_not_trusted(self):
        upload, download = self.records[2:4]
        analysis = {'flows': [{'links': [{'from_id': upload['observation_id'], 'to_id': download['observation_id'],
            'response_field': '$.invented', 'request_field': 'query.fileId'}]}]}
        self.assertFalse(EvidenceContext(self.clean, analysis).edges)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.candidates, self.records, _ = recommend(fixture(), ['example.test'])
        self.context = EvidenceContext(self.records)
        self.tasks, self.coverage = build_tasks(self.context, self.candidates)
        self.task = next(t for t in self.tasks if any('unitPriceOverride' in str(e) for e in t['evidence']))

    def test_rules_missed_record_becomes_only_an_anchored_hypothesis(self):
        added = hypotheses(result_for(self.task, True), self.task, self.context)
        c = added[0]
        self.assertEqual('llm_discovery', c['origin'])
        self.assertEqual('discovery_hypothesis', c['state'])
        self.assertEqual([fixture()[1]['observation_id']], c['subject_ids'])
        self.assertEqual(1, sum(set(t['eligible_subject_ids']) == set(self.task['eligible_subject_ids']) for t in self.tasks))
        self.assertFalse(c['confirmed']); self.assertFalse(c['reproduction_verified'])
        validate_refs(c, self.records)
        self.assertFalse(set(c['subject_ids']) & {oid for rule in self.candidates for oid in rule['subject_ids']})

    def test_empty_result_is_valid_and_not_a_safety_verdict(self):
        self.assertEqual([], hypotheses(result_for(self.task), self.task, self.context))

    def test_wrong_duplicate_invented_or_support_only_evidence_is_rejected(self):
        original = result_for(self.task, True); invalid = []
        value = copy.deepcopy(original); value['packet_id'] = 'f' * 64; invalid.append(value)
        value = copy.deepcopy(original); value['findings'][0]['evidence_ids'] = ['f' * 64]; invalid.append(value)
        value = copy.deepcopy(original); value['findings'][0]['evidence_ids'] *= 2; invalid.append(value)
        value = copy.deepcopy(original); value['findings'][0]['kind'] = 'request_smuggling'; invalid.append(value)
        value = copy.deepcopy(original); value['findings'][0]['confirmed'] = True; invalid.append(value)
        url = next(e for e in self.task['evidence'] if e['observation_id'] in original['findings'][0]['subject_ids'] and e['location'] == 'url')
        value = copy.deepcopy(original); value['findings'][0]['evidence_ids'] = [url['evidence_id']]; invalid.append(value)
        support = next(e for e in self.task['evidence'] if e['observation_id'] not in original['findings'][0]['subject_ids'])
        value = copy.deepcopy(original); value['findings'][0]['evidence_ids'] = [support['evidence_id']]; invalid.append(value)
        for value in invalid:
            with self.assertRaises(ValueError): validate(value, self.task)

    def test_allowed_owner_control_cannot_become_authorization_violation(self):
        task = next(t for t in self.tasks if any(r['expected_access'] == 'allow' and r['observation_id'] in t['eligible_subject_ids'] for r in t['records']))
        value = result_for(task, True); value['findings'][0]['kind'] = 'idor'
        with self.assertRaises(ValueError): validate(value, task)

    def test_provider_enum_is_bound_and_tampered_input_never_reaches_transport(self):
        def transport(prompt, schema, validator, *args, **kwargs):
            refs = schema['properties']['findings']['items']['properties']['evidence_ids']['items']['enum']
            self.assertEqual({r['evidence_id'] for r in self.task['evidence']}, set(refs))
            self.assertIn('도구·셸·브라우저', prompt)
            return validator(result_for(self.task)), {}
        with patch('recon81.codex_review._execute_json', side_effect=transport):
            self.assertEqual('verified', execute_discovery(self.task)[1]['discovery_validation'])
        task = copy.deepcopy(self.task); task['eligible_subject_ids'] = ['f' * 64]
        with patch('recon81.codex_review._execute_json') as transport:
            with self.assertRaises(ValueError): execute_discovery(task)
            transport.assert_not_called()


class CacheIdentityTests(unittest.TestCase):
    def test_rotating_proxy_credentials_reuse_only_the_same_route_and_configuration(self):
        def fingerprint(proxy, model=None, files=(('config', 'hash-a'),)):
            snapshot = ((('HTTPS_PROXY', proxy), ('HOME', '/test-home')), ('codex', 1), files)
            with patch('recon81.codex_review._configuration_snapshot', return_value=snapshot):
                return runtime_fingerprint(model)
        first = fingerprint('http://broker-a:token-a@proxy.test:8080')
        self.assertEqual(first, fingerprint('http://broker-b:token-b@proxy.test:8080'))
        self.assertNotEqual(first, fingerprint('http://broker-b:token-b@other.test:8080'))
        self.assertNotEqual(first, fingerprint('http://broker-b:token-b@proxy.test:8081'))
        self.assertEqual(fingerprint('http://local-a:token-a@127.0.0.1:40001'), fingerprint('http://local-b:token-b@127.0.0.1:40002'))
        self.assertNotEqual(first, fingerprint('http://broker-b:token-b@proxy.test:8080', model='changed'))
        self.assertNotEqual(first, fingerprint('http://broker-b:token-b@proxy.test:8080', files=(('config', 'hash-b'),)))


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.source = self.root / 'source'; self.cache = self.root / 'cache.sqlite3'
        generate(fixture(), self.source)
        self.addCleanup(patch.stopall)
        patch('recon81.candidate_intelligence.runtime_fingerprint', return_value='a' * 64).start()
        patch('recon81.candidate_cache.runtime_fingerprint', return_value='a' * 64).start()
        self.review = patch('recon81.candidate_report.execute_candidates', side_effect=reviewed).start()
        self.discover = patch('recon81.candidate_report.execute_discovery', side_effect=discovered).start()

    def create(self, name='result', **options):
        return create_recommendations(self.source, self.root / name, ['example.test'], **options)

    def test_shared_budget_and_cache_reuse_are_distinct_from_fresh_model_calls(self):
        first = self.create(ai=True, ai_limit=8, discover=True, discovery_limit=6, cache_path=self.cache)
        self.assertEqual(5, first['summary']['ai_new_units_selected'])
        self.assertEqual(4, first['summary']['discovery_new_tasks'])
        self.assertEqual(4, first['summary']['discovery_hypotheses'])
        self.review.reset_mock(); self.discover.reset_mock()
        second = self.create('again', ai=True, ai_limit=8, discover=True, discovery_limit=6, cache_path=self.cache)
        self.assertEqual(0, second['summary']['model_calls'])
        self.assertEqual(1, second['summary']['ai_reused_candidates'])
        self.assertEqual(4, second['summary']['discovery_reused_tasks'])
        self.assertTrue(all(e['fresh_model_execution'] is False for e in second['executions']))
        self.assertFalse((self.root / 'again/model-inputs').exists())
        self.review.assert_not_called(); self.discover.assert_not_called()

    def test_uncached_discovery_progresses_without_spending_budget_on_cached_tasks(self):
        first = self.create(ai=True, ai_limit=3, discover=True, discovery_limit=2, cache_path=self.cache)
        second = self.create('next', ai=True, ai_limit=3, discover=True, discovery_limit=2, cache_path=self.cache)
        self.assertEqual(3, first['summary']['ai_new_units_selected'])
        self.assertEqual(2, second['summary']['discovery_reused_tasks'])
        self.assertEqual(2, second['summary']['discovery_new_tasks'])
        self.assertLessEqual(second['summary']['ai_new_units_selected'], 3)

    def test_cache_corruption_expiry_and_runtime_changes_force_fresh_review(self):
        self.create(ai=True, cache_path=self.cache)
        with sqlite3.connect(self.cache) as db: db.execute("UPDATE model_cache SET sha256='invalid'")
        corrupted = self.create('corrupt', ai=True, cache_path=self.cache)
        self.assertEqual(1, corrupted['summary']['model_calls']); self.assertEqual(1, corrupted['summary']['cache_invalid_entries'])
        with sqlite3.connect(self.cache) as db: db.execute('UPDATE model_cache SET created=0')
        self.assertEqual(1, self.create('expired', ai=True, cache_path=self.cache)['summary']['model_calls'])
        with patch('recon81.candidate_intelligence.runtime_fingerprint', return_value='b' * 64):
            self.assertEqual(1, self.create('changed', ai=True, cache_path=self.cache)['summary']['model_calls'])

    def test_negative_discovery_results_are_reused_but_not_marked_safe(self):
        def empty(task, *args):
            result, receipt = discovered(task); return result_for(task), receipt
        self.discover.side_effect = empty
        self.create(ai=True, discover=True, discovery_limit=6, ai_limit=8, cache_path=self.cache)
        r = self.create('again', ai=True, discover=True, discovery_limit=6, ai_limit=8, cache_path=self.cache)
        self.assertEqual(0, r['summary']['discovery_hypotheses'])
        self.assertEqual(0, r['summary']['model_calls'])
        self.assertNotIn('safe', {row['discovery_status'] for row in r['records']})

    def test_prompt_content_changes_invalidate_reuse_without_manual_version_change(self):
        from recon81.candidate_review import prompt_for
        self.create(ai=True, cache_path=self.cache)
        with patch('recon81.candidate_intelligence.review_prompt', side_effect=lambda packet: prompt_for(packet) + '\nChanged instruction'):
            r = self.create('new-prompt', ai=True, cache_path=self.cache)
        self.assertEqual(1, r['summary']['model_calls'])

    def test_cache_write_problem_preserves_verified_fresh_results(self):
        with patch('recon81.candidate_cache.DecisionCache.put', return_value=None):
            r = self.create(ai=True, cache_path=self.cache)
        self.assertEqual(1, r['summary']['ai_fresh_reviewed_candidates'])
        self.assertEqual(0, r['summary']['ai_failed_packets'])

    def test_follow_up_is_ranked_first_without_treating_it_as_confirmed(self):
        r = self.create(ai=True, discover=True, ai_limit=8, discovery_limit=6)
        target = next(c for c in r['candidates'] if c['origin'] == 'llm_discovery')
        save_feedback(self.root / 'result', target['candidate_id'], 'follow_up', '담당자 후속 검토', self.root / 'feedback.json')
        again = self.create('ranked', ai=True, discover=True, ai_limit=8, discovery_limit=6, feedback_path=self.root / 'feedback.json')
        self.assertEqual(target['candidate_id'], again['candidates'][0]['candidate_id'])
        self.assertFalse(again['candidates'][0]['confirmed'])

    def test_invalid_receipt_or_result_is_never_cached_or_published_as_hypothesis(self):
        self.discover.side_effect = lambda task, *args: (result_for(task, True), {})
        r = self.create(ai=True, discover=True, discovery_limit=1, ai_limit=2, cache_path=self.cache)
        self.assertEqual(1, r['summary']['ai_failed_packets']); self.assertEqual(0, r['summary']['discovery_hypotheses'])
        with sqlite3.connect(self.cache) as db:
            self.assertEqual(1, db.execute('SELECT COUNT(*) FROM model_cache').fetchone()[0])  # only the valid rule review

    def test_human_dismissal_skips_model_but_preserves_candidate_and_source(self):
        first = self.create()
        c = first['candidates'][0]; feedback = self.root / 'feedback.json'
        source_bytes = (self.source / 'requests.jsonl').read_bytes()
        save_feedback(self.root / 'result', c['candidate_id'], 'dismiss', '정상 자료로 판단', feedback)
        self.review.reset_mock()
        r = self.create('human', ai=True, feedback_path=feedback)
        self.assertEqual(1, r['summary']['ai_human_dismissed_candidates'])
        self.assertEqual(1, len(r['candidates'])); self.assertEqual(0, r['summary']['model_calls'])
        self.assertEqual('dismiss', r['candidates'][0]['human_review']['decision'])
        self.assertEqual(source_bytes, (self.source / 'requests.jsonl').read_bytes())
        self.review.assert_not_called()

    def test_feedback_requires_matching_full_evidence_and_manifest(self):
        r = self.create(); c = r['candidates'][0]; path = self.root / 'feedback.json'
        save_feedback(self.root / 'result', c['candidate_id'], 'follow_up', '독립 검토 필요', path)
        changed = copy.deepcopy(r['candidates']); changed[0]['evidence_digest'] = 'f' * 64
        summary = apply_feedback(changed, read_feedback(path))
        self.assertEqual(0, summary['applied']); self.assertEqual(1, summary['stale_or_unmatched_entries'])
        (self.root / 'result/recommendations.json').write_text('{}')
        with self.assertRaises(ValueError): save_feedback(self.root / 'result', c['candidate_id'], 'dismiss', '변조', path)

    def test_feedback_append_history_and_immutable_report_path_protection(self):
        c = self.create()['candidates'][0]; path = self.root / 'feedback.json'
        for decision in ('needs_context', 'follow_up'):
            save_feedback(self.root / 'result', c['candidate_id'], decision, '검토 기록', path)
        self.assertEqual(2, len(read_feedback(path)['entries']))
        with self.assertRaises(ValueError): save_feedback(self.root / 'result', c['candidate_id'], 'dismiss', '보호', self.root / 'result/index.html')
        with self.assertRaises(ValueError): self.create('bad', ai=True, cache_path=self.source / 'cache.sqlite3')

    def test_cli_feedback_and_cache_opt_out_and_discovery_requires_ai(self):
        c = self.create()['candidates'][0]
        with patch('sys.stdout', new_callable=io.StringIO):
            status = main(['feedback','--review',str(self.root / 'result'),'--candidate-id',c['candidate_id'],
                '--decision','follow_up','--note','검토 필요','--output',str(self.root / 'feedback.json')])
        self.assertEqual(0, status)
        with self.assertRaises(ValueError): self.create('bad', discover=True)
        with patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(0, main(['recommend','--report',str(self.source),'--scope','example.test','--output',str(self.root / 'cli'), '--ai','--no-cache']))
        self.assertFalse((self.root / 'candidate-ai-cache.sqlite3').exists())

    def test_saved_only_pipeline_never_uses_target_network(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('No target DNS')):
            with patch('socket.create_connection', side_effect=AssertionError('No target connection')):
                r = self.create(ai=True, discover=True, ai_limit=8, discovery_limit=6)
        self.assertEqual(0, r['summary']['target_requests_sent']); self.assertEqual(0, r['summary']['target_dns_lookups'])
        self.assertTrue((self.root / 'result/model-results').is_dir())
        html = (self.root / 'result/index.html').read_text()
        self.assertIn('AI 탐색 가설', html); self.assertIn('관련 저장 증거', html)
        self.assertTrue((self.root / 'result/evidence-records').is_dir())


if __name__ == '__main__': unittest.main()
