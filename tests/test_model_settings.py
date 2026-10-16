"""Observe child arguments and receipts without connecting to any model or target."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon81.codex_review import _execute_json, diagnose
from recon81.candidate_cache import runtime_fingerprint, DecisionCache


class ModelSettingsTests(unittest.TestCase):
    def test_shared_transport_pins_settings_and_records_requested_identity(self):
        def process(args, cwd, timeout, prompt=None, **kwargs):
            self.assertEqual('gpt-6.1-sol', args[args.index('--model') + 1])
            configs = [args[i + 1] for i, value in enumerate(args[:-1]) if value == '-c']
            self.assertEqual('model_reasoning_effort="medium"', configs[-1])
            self.assertIn('--sandbox', args)
            self.assertEqual('read-only', args[args.index('--sandbox') + 1])
            self.assertEqual('-', args[-1])
            Path(args[args.index('-o') + 1]).write_text('{"ready":true}')
            return '\n'.join(json.dumps(e) for e in [
                {'type': 'item.completed', 'item': {'type': 'agent_message'}},
                {'type': 'turn.completed'}]), ''
        schema = {'type': 'object', 'properties': {'ready': {'type': 'boolean'}},
                  'required': ['ready'], 'additionalProperties': False}
        with patch('recon81.codex_review._configuration', return_value=[
                '-c', 'model_reasoning_effort="high"']), \
                patch('recon81.codex_review._process', side_effect=process):
            result, receipt = _execute_json('Synthetic readiness fixture.', schema, lambda x: x)
        self.assertTrue(result['ready'])
        self.assertEqual('gpt-6.1-sol', receipt['requested_model'])
        self.assertEqual('medium', receipt['requested_reasoning_effort'])
        self.assertTrue(receipt['completion_events_verified'])

    def test_doctor_reports_selected_settings_without_calling_a_model(self):
        def process(args, *unused):
            self.assertEqual(['codex', '--version'], args)
            return 'codex-cli 0.162.1\n', ''
        with patch('recon81.codex_review._process', side_effect=process) as cli, \
                patch('recon81.codex_review._configuration', return_value=[]):
            report = diagnose()
        self.assertEqual('ready', report['status'])
        self.assertEqual('gpt-6.1-sol', report['requested_model'])
        self.assertEqual('medium', report['requested_reasoning_effort'])
        self.assertFalse(report['model_execution_verified'])
        self.assertEqual(1, cli.call_count)

    def test_cache_identity_includes_resolved_model_and_reasoning_effort(self):
        snapshot = ((), ('synthetic-cli', 1), ())
        with patch('recon81.codex_review._configuration_snapshot', return_value=snapshot):
            baseline = runtime_fingerprint()
            self.assertEqual(baseline, runtime_fingerprint('gpt-6.1-sol'))
            self.assertNotEqual(baseline, runtime_fingerprint('another-model'))
            with patch('recon81.candidate_cache.DEFAULT_REASONING_EFFORT', 'high'):
                self.assertNotEqual(baseline, runtime_fingerprint())

    def test_cache_does_not_store_receipts_with_unknown_reasoning(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = DecisionCache(Path(directory) / 'cache.sqlite3', 'test')
            try:
                cache.put('candidate', {}, {}, {}, {'requested_model': 'gpt-6.1-sol'})
                self.assertEqual(0, cache.conn.execute('SELECT count(*) FROM model_cache').fetchone()[0])
            finally:
                cache.close()
