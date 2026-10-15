"""Run-scoped adapter preflight and monitored legacy execution; no CLI/model calls."""
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from contextvars import copy_context
from pathlib import Path
from unittest.mock import patch

from recon81.ai_review import build_packet, load_json
from recon81.codex_review import (
    ReviewFailure, _configuration, _process, configuration_session, execute_packet, run_review,
)
from recon81.core import normalize_record
from recon81.reports import generate
from recon81.review_batch import prepare_batch, verify_batch


EVENTS = [
    {'type': 'item.completed', 'item': {'type': 'agent_message'}},
    {'type': 'turn.completed'},
]


class WaitingProcess:
    """A local fake process that emits fixed events and then waits until stopped."""
    def __init__(self, events):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(b''.join(json.dumps(event).encode() + b'\n' for event in events))
        self.stderr = io.BytesIO()
        self.returncode = None
        self.stopped = threading.Event()

    def wait(self, timeout=None):
        if not self.stopped.wait(timeout):
            raise subprocess.TimeoutExpired(['offline-adapter'], timeout)
        return self.returncode

    def stop(self):
        self.returncode = -9
        self.stopped.set()


class CodexTransportV86Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / 'codex-home'
        self.home.mkdir()
        self.environment = patch.dict(os.environ, {
            'HOME': str(self.root), 'CODEX_HOME': str(self.home), 'PATH': '',
        }, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.tmp.cleanup)

    def preflight(self, args, cwd, timeout, prompt=None, **kwargs):
        if args[1:3] == ['login', 'status']:
            return '', 'Logged in using ChatGPT'
        if args[1:3] == ['features', 'list']:
            return 'shell_tool stable true\napps experimental true\n', ''
        if args[1:3] == ['mcp', 'list']:
            return '[{"name":"saved_server"}]', ''
        self.fail('Unexpected process request in preflight-only test')

    def make_report(self):
        report = self.root / 'source'
        record = normalize_record('https://example.test/public', 'GET', response={
            'status': 200, 'headers': {'Content-Type': 'application/json'}, 'body': '{"public":true}',
        }, source='offline_transport_fixture')
        generate([record], report)
        return report

    def test_equal_deadlines_preserve_observed_execution_state(self):
        for events, expected in [
            ([], ('CLI_EVENT_TIMEOUT', 'startup')),
            ([{'type': 'turn.started'}], ('FIRST_RESPONSE_TIMEOUT', 'response')),
            ([{'type': 'item.started', 'item': {'type': 'reasoning'}}], ('EXECUTION_TIMEOUT', 'response')),
        ]:
            process = WaitingProcess(events)
            with self.subTest(expected=expected), \
                    patch('recon81.codex_review.subprocess.Popen', return_value=process), \
                    patch('recon81.codex_review._stop', side_effect=lambda child: child.stop()):
                with self.assertRaises(ReviewFailure) as caught:
                    _process(['offline-adapter'], self.root, .05, on_event=lambda event: None,
                             first_response_timeout=.05)
            self.assertEqual(expected, (caught.exception.code, caught.exception.stage))
            self.assertEqual(bool(events), bool(caught.exception.diagnostic['execution_events_received']))
            self.assertEqual(expected[0] == 'EXECUTION_TIMEOUT', caught.exception.diagnostic['model_response_seen'])

    def test_response_deadline_alone_monitors_events_and_total_limit_stays_bounded(self):
        process = WaitingProcess([{'type': 'turn.started'}])
        with patch('recon81.codex_review.subprocess.Popen', return_value=process), \
                patch('recon81.codex_review._stop', side_effect=lambda child: child.stop()):
            with self.assertRaises(ReviewFailure) as caught:
                _process(['offline-adapter'], self.root, .05, first_response_timeout=5)
        self.assertEqual(('FIRST_RESPONSE_TIMEOUT', 'response'), (caught.exception.code, caught.exception.stage))

    def test_preflight_process_timeout_retains_execution_timeout(self):
        process = WaitingProcess([])
        with patch('recon81.codex_review.subprocess.Popen', return_value=process), \
                patch('recon81.codex_review._stop', side_effect=lambda child: child.stop()):
            with self.assertRaises(ReviewFailure) as caught:
                _process(['offline-adapter'], self.root, .05)
        self.assertEqual('EXECUTION_TIMEOUT', caught.exception.code)

    def test_legacy_and_batch_share_monitored_execution_and_schema_validation(self):
        report = self.make_report()
        batch = self.root / 'batch'
        prepare_batch(report, batch, ['example.test'])
        pid = verify_batch(batch)['packets'][0]['packet_id']
        packet = load_json(batch / 'packets' / pid / 'packet.json')
        monitored = []

        def adapter(args, cwd, timeout, prompt=None, **kwargs):
            if 'exec' not in args:
                return self.preflight(args, cwd, timeout, prompt, **kwargs)
            self.assertTrue(callable(kwargs['on_event']))
            self.assertEqual(10, kwargs['first_response_timeout'])
            self.assertIn('features.shell_tool=false', args)
            self.assertIn('mcp_servers.saved_server.enabled=false', args)
            self.assertIn('read-only', args)
            self.assertIn('--ephemeral', args)
            schema = load_json(Path(args[args.index('--output-schema') + 1]))
            selected = json.loads(prompt.split('UNTRUSTED_EVIDENCE_JSON\n', 1)[1])
            self.assertEqual(selected['schema_version'] == '8.5',
                             'citations' in schema['properties']['reviews']['items']['required'])
            kwargs['on_event']({'type': 'turn.started', 'item_type': ''})
            kwargs['on_event']({'type': 'item.completed', 'item_type': 'agent_message'})
            value = {'packet_id': selected['packet_id'], 'summary': 'Offline fixture.', 'reviews': []}
            Path(args[args.index('-o') + 1]).write_text(json.dumps(value))
            monitored.append(selected['schema_version'])
            return '\n'.join(map(json.dumps, EVENTS)), ''

        with patch('recon81.codex_review._process', side_effect=adapter):
            run_review(report, self.root / 'legacy', ['example.test'], timeout=10)
            _, receipt = execute_packet(packet, timeout=10)
        self.assertEqual(['8.4', '8.5'], monitored)
        self.assertEqual('legacy_unverified', load_json(self.root / 'legacy' / 'execution.json')['citation_validation'])
        self.assertEqual('verified', receipt['citation_validation'])

    def test_legacy_tool_event_stops_process_before_publication(self):
        report = self.make_report()
        process = WaitingProcess([{'type': 'item.started', 'item': {'type': 'command_execution'}}])
        with patch('recon81.codex_review._configuration', return_value=[]), \
                patch('recon81.codex_review.subprocess.Popen', return_value=process), \
                patch('recon81.codex_review._stop', side_effect=lambda child: child.stop()):
            with self.assertRaises(ReviewFailure) as caught:
                run_review(report, self.root / 'rejected', ['example.test'], timeout=10)
        self.assertEqual('TOOL_ACTIVITY_BLOCKED', caught.exception.code)
        self.assertTrue(process.stopped.is_set())
        self.assertFalse((self.root / 'rejected').exists())

    def test_legacy_invalid_completion_never_publishes(self):
        report = self.make_report()

        def invalid(args, cwd, timeout, prompt=None, **kwargs):
            Path(args[args.index('-o') + 1]).write_text(json.dumps({
                'packet_id': build_packet(report, ['example.test'])['packet_id'],
                'summary': 'Untrusted incomplete receipt.', 'reviews': [],
            }))
            return '{"type":"turn.completed"}\n', ''

        with patch('recon81.codex_review._configuration', return_value=[]), \
                patch('recon81.codex_review._process', side_effect=invalid):
            with self.assertRaises(ReviewFailure) as caught:
                run_review(report, self.root / 'incomplete', ['example.test'])
        self.assertEqual('completion_validation', caught.exception.stage)
        self.assertFalse((self.root / 'incomplete').exists())

    def test_configuration_cache_is_run_scoped_and_returns_flag_copies(self):
        with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
            with configuration_session():
                first = _configuration(self.root / 'packet-one')
                first.append('MUTATED_BY_CALLER')
                stages = []
                second = _configuration(self.root / 'packet-two', stages.append)
                self.assertNotIn('MUTATED_BY_CALLER', second)
                self.assertEqual(3, process.call_count)
                self.assertEqual(['authentication', 'capabilities', 'mcp_configuration'], stages)
            _configuration(self.root)
            self.assertEqual(6, process.call_count)
            with configuration_session():
                _configuration(self.root)
                self.assertEqual(9, process.call_count)

    def test_configuration_and_credential_changes_require_new_preflight(self):
        with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
            with configuration_session():
                _configuration(self.root)
                for filename in ('config.toml', 'auth.json'):
                    (self.home / filename).write_text('offline-fixture')
                    _configuration(self.root)
                self.assertEqual(9, process.call_count)
                with patch.dict(os.environ, {'HTTPS_PROXY': 'http://fixture.invalid:8080'}):
                    _configuration(self.root)
                self.assertEqual(12, process.call_count)

    def test_authentication_failure_is_not_cached(self):
        with configuration_session():
            with patch('recon81.codex_review._process', return_value=('', 'Logged in using an API key')):
                with self.assertRaises(ReviewFailure) as caught:
                    _configuration(self.root)
            self.assertEqual('CHATGPT_AUTH_REQUIRED', caught.exception.code)
            with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
                _configuration(self.root)
                self.assertEqual(3, process.call_count)

    def test_mcp_failure_is_not_cached_and_never_supplies_flags(self):
        def invalid(args, cwd, timeout, prompt=None, **kwargs):
            if args[1:3] == ['mcp', 'list']:
                return '[{"name":"unsupported.name"}]', ''
            return self.preflight(args, cwd, timeout, prompt, **kwargs)

        with configuration_session():
            with patch('recon81.codex_review._process', side_effect=invalid):
                with self.assertRaises(ValueError):
                    _configuration(self.root)
            with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
                flags = _configuration(self.root)
                self.assertIn('mcp_servers.saved_server.enabled=false', flags)
                self.assertEqual(3, process.call_count)

    def test_configuration_changed_during_preflight_is_rejected(self):
        def changed(args, cwd, timeout, prompt=None, **kwargs):
            if args[1:3] == ['mcp', 'list']:
                (self.home / 'config.toml').write_text('new-configuration')
            return self.preflight(args, cwd, timeout, prompt, **kwargs)

        with configuration_session():
            with patch('recon81.codex_review._process', side_effect=changed):
                with self.assertRaises(ReviewFailure) as caught:
                    _configuration(self.root)
            self.assertEqual('CLI_CONFIGURATION_CHANGED', caught.exception.code)
            with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
                _configuration(self.root)
                self.assertEqual(3, process.call_count)

    def test_session_exit_invalidates_retained_context_after_failure(self):
        with patch('recon81.codex_review._process', side_effect=self.preflight) as process:
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                with configuration_session():
                    _configuration(self.root)
                    retained = copy_context()
                    raise RuntimeError('fixture')
            retained.run(_configuration, self.root)
            self.assertEqual(6, process.call_count)


if __name__ == '__main__':
    unittest.main()
