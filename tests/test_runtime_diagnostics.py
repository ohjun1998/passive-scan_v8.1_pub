"""Adapter failures and receipt provenance; no actual model or target calls."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_review import main
from recon81.ai_review import load_json
from recon81.codex_review import diagnose, execute_packet, ReviewFailure
from recon81.context import attach_context
from recon81.core import normalize_record
from recon81.reports import generate
from recon81.review_batch import prepare_batch, run_batch, verify_batch
from recon81.review_reporting import batch_report, evaluate


EVENTS = '\n'.join(json.dumps(e) for e in [
    {'type': 'item.completed', 'item': {'type': 'agent_message'}}, {'type': 'turn.completed'}])


def adapter(args, cwd, timeout, prompt=None, **kwargs):
    if args[1:] == ['--version']:
        return 'codex-cli 0.162.1\n', ''
    if args[1:3] == ['login', 'status']:
        return '', 'Logged in using ChatGPT'
    if args[1:3] == ['features', 'list']:
        return 'shell_tool stable true\n', ''
    if args[1:3] == ['mcp', 'list']:
        return '[]', ''
    Path(args[args.index('-o') + 1]).write_text('{"ready":true}')
    return EVENTS, ''


def opinion(packet):
    record = packet['evidence'][0]
    return {'packet_id': packet['packet_id'], 'summary': 'Adapter test fixture, no real model.', 'reviews': [{
        'observation_ids': [record['observation_id']], 'assessment': 'likely_benign', 'confidence': 'low',
        'reason': 'Fixture only.', 'evidence_notes': ['Saved public field.'], 'next_checks': ['Check policy.'],
        'citations': [{'observation_id': record['observation_id'], 'location': 'response.body.json',
                       'pointer': '/public', 'excerpt': 'true'}],
        'report_draft': {'title': 'Fixture', 'impact': 'Unknown', 'steps': ['Read saved response'],
                         'expected': 'Public data', 'actual': 'Public field', 'remediation': 'Review policy'}}]}


class RuntimeDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def batch(self, name='batch'):
        records = [attach_context(normalize_record('https://example.test/' + name + str(i), 'GET',
            response={'status': 200, 'headers': {'Content-Type': 'application/json'}, 'body': '{"public":true}'},
            source='synthetic_runtime_test'), {'actor': 'anonymous'}) for i in range(2)]
        generate(records, self.root / (name + '-base'))
        prepare_batch(self.root / (name + '-base'), self.root / name, ['example.test'])
        return self.root / name
    def test_configuration_check_makes_no_model_request(self):
        with patch('recon81.codex_review._process', side_effect=adapter) as process:
            result = diagnose()
        self.assertEqual('ready', result['status'])
        self.assertEqual(4, process.call_count)
        self.assertFalse(result['model_execution_verified'])
        self.assertFalse(result['evidence_sent'])
        self.assertEqual(['cli', 'authentication', 'capabilities', 'mcp_configuration'], result['checks'])
    def test_missing_cli_is_safe_and_cli_returns_failure(self):
        output = io.StringIO()
        with patch('recon81.codex_review._process', side_effect=FileNotFoundError('NEVER_SAVE')), contextlib.redirect_stdout(output):
            status = main(['doctor', '--output', str(self.root / 'diagnostic')])
        value = json.loads(output.getvalue())
        self.assertEqual(2, status)
        self.assertEqual(('CLI_NOT_FOUND', 'cli'), (value['code'], value['stage']))
        self.assertNotIn('NEVER_SAVE', output.getvalue())
        self.assertEqual(value, load_json(self.root / 'diagnostic/diagnostic.json'))
    def test_probe_requires_receipt_and_exact_boolean(self):
        with patch('recon81.codex_review._process', side_effect=adapter):
            result = diagnose(probe=True, timeout=10, first_response_timeout=90)
        self.assertTrue(result['model_execution_verified'])
        self.assertFalse(result['subscription_plan_verified'])
        def wrong(*args, **kwargs):
            result = adapter(*args, **kwargs)
            if 'exec' in args[0]:
                Path(args[0][args[0].index('-o') + 1]).write_text('{"ready":1}')
            return result
        with patch('recon81.codex_review._process', side_effect=wrong):
            self.assertEqual('INVALID_PROBE_RESULT', diagnose(probe=True)['code'])
    def test_failed_probe_preserves_known_stage_without_stderr(self):
        def failed(*args, **kwargs):
            if 'exec' in args[0]:
                raise ReviewFailure('FIRST_RESPONSE_TIMEOUT', 'response')
            return adapter(*args, **kwargs)
        with patch('recon81.codex_review._process', side_effect=failed):
            result = diagnose(probe=True)
        self.assertEqual(('failed', 'FIRST_RESPONSE_TIMEOUT', 'response'), (result['status'], result['code'], result['stage']))
        self.assertFalse(result['model_execution_verified'])
    def test_invalid_model_is_not_copied_to_diagnostic(self):
        with patch('recon81.codex_review._process') as process:
            value = diagnose(model='NEVER_SAVE/invalid')
        self.assertEqual('INVALID_MODEL_ID', value['code'])
        self.assertNotIn('NEVER_SAVE', json.dumps(value))
        process.assert_not_called()
    def test_missing_result_is_distinct_from_missing_cli(self):
        directory = self.batch()
        pid = verify_batch(directory)['packets'][0]['packet_id']
        packet = load_json(directory / 'packets' / pid / 'packet.json')
        with patch('recon81.codex_review._configuration', return_value=[]), patch('recon81.codex_review._process', return_value=(EVENTS, '')):
            with self.assertRaises(ReviewFailure) as caught:
                execute_packet(packet)
        self.assertEqual(('RESULT_MISSING', 'citation_validation'), (caught.exception.code, caught.exception.stage))
    def test_custom_response_deadline_is_clamped_and_persisted(self):
        directory = self.batch()
        def fail(packet, timeout, model, progress, first_response_timeout):
            self.assertEqual(90, first_response_timeout)
            raise ReviewFailure('FIRST_RESPONSE_TIMEOUT', 'response')
        with patch('recon81.codex_review.execute_packet', side_effect=fail):
            result = run_batch(directory, timeout=20, first_response_timeout=90)
        pid = result['packets'][0]['packet_id']
        attempt = load_json(directory / 'attempts' / pid / 'history.json')[0]
        self.assertEqual(20, attempt['settings']['first_response_timeout'])
        with patch('recon81.codex_review.execute_packet') as process:
            with self.assertRaises(ReviewFailure):
                run_batch(directory, first_response_timeout=0)
            process.assert_not_called()
    def test_batch_default_waits_for_saved_evidence_reasoning_and_records_its_bound(self):
        directory = self.batch()
        def fail(packet, timeout, model, progress, first_response_timeout):
            self.assertEqual(300, timeout)
            self.assertEqual(180, first_response_timeout)
            raise ReviewFailure('FIRST_RESPONSE_TIMEOUT', 'response')
        with patch('recon81.codex_review.execute_packet', side_effect=fail):
            result = run_batch(directory)
        pid = result['packets'][0]['packet_id']
        attempt = load_json(directory / 'attempts' / pid / 'history.json')[0]
        self.assertEqual({'timeout': 300, 'first_response_timeout': 180, 'requested_model': None},
                         attempt['settings'])
    def test_cli_batch_default_is_longer_than_the_evidence_free_doctor_probe(self):
        summary = {'summary': {'completed_packets': 1, 'packets': 1}}
        with patch('recon81.review_batch.run_batch', return_value=summary) as batch_run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(['batch-run', '--batch', 'offline-fixture']))
        batch_run.assert_called_once_with('offline-fixture', 300, None, False, 3, 180)
        with patch('recon81.codex_review.diagnose', return_value={'status': 'ready'}) as doctor, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(['doctor', '--probe']))
        doctor.assert_called_once_with(True, 60, None, 60)
    def test_batch_receipts_and_evaluation_distinguish_fixture_from_codex(self):
        for name, verified in [('fixture', False), ('verified', True)]:
            directory = self.batch(name)
            receipt = {'provider': 'codex_chatgpt_login' if verified else 'test_fixture', 'status': 'completed',
                       'model_execution_verified': True, 'completion_events_verified': True, 'citation_validation': 'verified'}
            with patch('recon81.codex_review.execute_packet', side_effect=lambda p, *args: (opinion(p), receipt)):
                run_batch(directory)
            snapshot = self.root / (name + '-report')
            batch_report(directory, snapshot)
            execution = load_json(snapshot / 'execution.json')
            self.assertEqual(verified, execution['model_execution_verified'])
            self.assertEqual(2 if verified else 0, execution['packet_execution_counts']['codex_verified'])
            oid = verify_batch(directory)['records'][0]['observation_id']
            labels = self.root / (name + '-labels.json')
            labels.write_text(json.dumps({'provenance': 'Independent fixture contract', 'cases': [
                {'case_id': 'public', 'observation_ids': [oid], 'expected_assessment': 'likely_benign', 'category': 'public'}]}))
            result = evaluate(snapshot, labels, self.root / (name + '-evaluation'))
            self.assertEqual(verified, result['execution_provenance']['model_execution_verified'])
    def test_incomplete_batch_cli_keeps_nonzero_exit(self):
        directory = self.batch()
        with patch('recon81.codex_review.execute_packet', side_effect=ReviewFailure('NETWORK_ERROR', 'response')), contextlib.redirect_stdout(io.StringIO()):
            status = main(['batch-run', '--batch', str(directory)])
        self.assertEqual(3, status)


if __name__ == '__main__':
    unittest.main()
