import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from recon81.core import normalize_record, digest
from recon81.context import attach_context
from recon81.reports import generate
from recon81.ai_review import build_packet, prepare_review, import_review, load_json, validate_result, verify_packet
from recon81.codex_review import make_prompt, run_review, _validate_events, _process, _environment

PROJECT = Path(__file__).resolve().parents[1]


def record(url='https://example.test/api/orders/123', actor='user-b', text=None, mime='application/json'):
    return attach_context(normalize_record(url=url, method='GET', headers={'Authorization': 'Bearer NEVER_SAVE'},
        response={'status': 200, 'headers': {'Content-Type': mime, 'Set-Cookie': 'NEVER_SAVE'},
                  'body': text or '{"id":123,"ownerId":"user-a","passwordHash":"NEVER_SAVE"}'},
        include_text=True, source='har'), {'actor': actor, 'expected_access': 'deny'})


def result(packet):
    return {'packet_id': packet['packet_id'], 'summary': '모의 결과. 실제 모델 호출 없음.', 'reviews': [{
        'observation_ids': [packet['evidence'][0]['observation_id']], 'assessment': 'suspicious', 'confidence': 'low',
        'reason': '노출 관찰과 권한 정책 확인을 구분해야 함.', 'evidence_notes': ['$.passwordHash: [REDACTED]'],
        'next_checks': ['계정 신원과 접근 정책을 확인'], 'report_draft': {
            'title': 'API 응답 정보 노출 후보', 'impact': '권한·영향 미확인', 'steps': ['저장된 응답 확인'],
            'expected': '정책 확인 필요', 'actual': '필드 존재 관찰', 'remediation': '응답 DTO 필드 제한 검토'}}]}


class AIReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.report = self.root / 'base'
        generate([record(), record('https://other.test/private')], self.report)
        self.packet = build_packet(self.report, ['example.test'])
    def tearDown(self):
        self.tmp.cleanup()
    def test_prepare_and_import_end_to_end_preserves_base(self):
        before = {p.name: p.read_bytes() for p in self.report.iterdir() if p.is_file()}
        prepared = self.root / 'prepared'
        prepare_review(self.report, prepared, ['example.test'])
        answer = self.root / 'answer.json'; answer.write_text(json.dumps(result(self.packet)))
        import_review(prepared / 'packet.json', answer, self.root / 'ai')
        execution = load_json(self.root / 'ai/execution.json')
        self.assertFalse(execution['model_execution_verified'])
        self.assertTrue(execution['human_confirmation_required'])
        self.assertEqual(0, execution['target_requests_sent'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.report.iterdir() if p.is_file()})
    def test_packet_filters_scope_and_masks_credentials(self):
        encoded = json.dumps(self.packet)
        self.assertNotIn('NEVER_SAVE', encoded)
        self.assertNotIn('other.test', encoded)
        self.assertEqual(1, self.packet['omissions']['out_of_scope'])
        self.assertTrue(self.packet['source_manifest_verified'])
    def test_changed_source_receipt_rejected(self):
        with (self.report / 'requests.jsonl').open('a') as out: out.write('\n')
        with self.assertRaises(ValueError): build_packet(self.report, ['example.test'])
    def test_legacy_source_allowed_with_explicit_unverified_receipt(self):
        (self.report / 'manifest.json').unlink()
        self.assertFalse(build_packet(self.report, ['example.test'])['source_manifest_verified'])
    def test_packet_budget_and_truncation(self):
        generate([record(text='x'*20000, mime='text/html')], self.root / 'large')
        packet = build_packet(self.root / 'large', ['example.test'], max_bytes=16384)
        self.assertLessEqual(len(json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2).encode())+1, 16384)
        self.assertFalse(packet['evidence'][0]['response']['body']['complete'])
        self.assertEqual('ai_body_byte_limit', packet['evidence'][0]['response']['body']['reason'])
    def test_record_limit_reports_omissions(self):
        generate([record('https://example.test/'+str(i)) for i in range(5)], self.root / 'five')
        packet = build_packet(self.root / 'five', ['example.test'], max_records=2)
        self.assertEqual(2, len(packet['evidence']))
        self.assertEqual(3, packet['omissions']['records'])
    def test_missing_body_remains_missing(self):
        generate([normalize_record(url='https://example.test/a', method='UNKNOWN', source='url', observed=False)], self.root / 'static')
        packet = build_packet(self.root / 'static', ['example.test'])
        self.assertFalse(packet['evidence'][0]['observed'])
        self.assertIsNone(packet['evidence'][0]['response'])
    def test_modified_packet_rejected(self):
        packet = copy.deepcopy(self.packet); packet['evidence'][0]['method'] = 'POST'
        with self.assertRaises(ValueError): verify_packet(packet)
    def test_invalid_result_boundaries(self):
        answer = result(self.packet)
        for change in ('extra', 'packet', 'evidence', 'confirmed', 'duplicate', 'too_long', 'missing', 'type'):
            bad = copy.deepcopy(answer)
            if change == 'extra': bad['severity'] = 'critical'
            elif change == 'packet': bad['packet_id'] = '0'*64
            elif change == 'evidence': bad['reviews'][0]['observation_ids'] = ['0'*64]
            elif change == 'confirmed': bad['reviews'][0]['assessment'] = 'confirmed'
            elif change == 'duplicate': bad['reviews'][0]['observation_ids'] *= 2
            elif change == 'too_long': bad['summary'] = 'x'*8001
            elif change == 'missing': del bad['reviews'][0]['report_draft']['impact']
            elif change == 'type': bad['reviews'][0]['next_checks'] = 'not an array'
            with self.subTest(change=change), self.assertRaises(ValueError): validate_result(bad, self.packet)
    def test_json_duplicates_and_nan_rejected(self):
        path = self.root / 'invalid.json'
        for text in ('{"x":1,"x":2}', '{"x":NaN}'):
            path.write_text(text)
            with self.assertRaises(ValueError): load_json(path)
    def test_no_overwrite_and_html_escaped(self):
        prepare_review(self.report, self.root / 'prepared', ['example.test'])
        with self.assertRaises(ValueError): prepare_review(self.report, self.root / 'prepared', ['example.test'])
        answer = result(self.packet); answer['summary'] = '<script>alert(1)</script>'
        path = self.root / 'answer.json'; path.write_text(json.dumps(answer))
        import_review(self.root / 'prepared/packet.json', path, self.root / 'ai')
        page = (self.root / 'ai/index.html').read_text()
        self.assertNotIn('<script>', page); self.assertIn('&lt;script&gt;', page)
    def test_prompt_preserves_json_and_contains_disclosure_instructions(self):
        prompt = make_prompt(self.packet)
        self.assertEqual(self.packet, json.loads(prompt.split('UNTRUSTED_EVIDENCE_JSON\n', 1)[1]))
        for text in ('API 응답', 'JavaScript·HTML', '오류 메시지', '도구, 셸', '유효성', '신원 미검증'):
            self.assertIn(text, prompt)
    def test_model_environment_does_not_pass_api_keys(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'NEVER_SAVE', 'MY_SECRET': 'NEVER_SAVE'}):
            self.assertNotIn('OPENAI_API_KEY', _environment())
            self.assertNotIn('MY_SECRET', _environment())
    def test_codex_model_plan_is_not_model_id(self):
        with self.assertRaises(ValueError): run_review(self.report, self.root / 'ai', ['example.test'], model='pro')
    def test_tool_and_incomplete_events_rejected(self):
        for events in ([{'type':'turn.completed'}], [{'type':'item.completed','item':{'type':'command_execution'}}],
                       [{'type':'error','message':'captured secret'}]):
            with self.assertRaises(ValueError): _validate_events('\n'.join(json.dumps(e) for e in events))
    def test_subprocess_timeout_and_output_limit(self):
        with self.assertRaises(ValueError): _process([sys.executable, '-c', 'import time; time.sleep(2)'], self.root, .05)
        with self.assertRaises(ValueError): _process([sys.executable, '-c', 'print("x"*2200000)'], self.root, 5)
    def test_cli_failure_does_not_print_evidence(self):
        done = subprocess.run([sys.executable, str(PROJECT/'ai_review.py'), 'prepare', '--report', str(self.report),
                               '--output', str(self.root/'ai'), '--scope', 'none.test'], capture_output=True, text=True)
        self.assertEqual(2, done.returncode); self.assertNotIn('NEVER_SAVE', done.stderr)
    def test_mock_codex_completion_and_auth_guard(self):
        # Fake CLI verifies adapter wiring only, never model detection quality.
        def fake(args, cwd, timeout, prompt=None, **kwargs):
            if args[1:3] == ['login', 'status']: return '', 'Logged in using ChatGPT'
            if args[1:3] == ['features', 'list']: return 'shell_tool stable true\napps experimental true', ''
            if args[1:3] == ['mcp', 'list']: return '[{"name":"server"}]', ''
            self.assertIn('features.shell_tool=false', args)
            self.assertIn('mcp_servers.server.enabled=false', args)
            self.assertIn('--ephemeral', args)
            self.assertTrue(callable(kwargs['on_event']))
            self.assertIn('read-only', args)
            packet = json.loads(prompt.split('UNTRUSTED_EVIDENCE_JSON\n')[1])
            Path(args[args.index('-o')+1]).write_text(json.dumps(result(packet)))
            return '\n'.join(json.dumps(e) for e in [
                {'type':'item.completed','item':{'type':'agent_message'}}, {'type':'turn.completed'}]), ''
        with patch('recon81.codex_review._process', side_effect=fake):
            run_review(self.report, self.root / 'mock', ['example.test'])
        receipt = load_json(self.root / 'mock/execution.json')
        self.assertTrue(receipt['model_execution_verified'])
        self.assertFalse(receipt['subscription_plan_verified'])
        with patch('recon81.codex_review._process', return_value=('', 'Logged in using an API key')):
            with self.assertRaises(ValueError): run_review(self.report, self.root / 'bad', ['example.test'])
        self.assertFalse((self.root / 'bad').exists())


if __name__ == '__main__': unittest.main()
