"""Provider schema compatibility with the original local result contract intact."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon81.ai_review import SCHEMA, build_packet, load_json, validate_result
from recon81.codex_review import ReviewFailure, _process, _provider_schema, execute_packet, run_review
from recon81.core import normalize_record
from recon81.reports import generate
from recon81.review_batch import prepare_batch, verify_batch
from recon81.review_evidence import SCHEMA85


class SchemaCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.report = self.root / 'source'
        record = normalize_record('https://example.test/public', 'GET', response={
            'status': 200, 'headers': {'Content-Type': 'application/json'}, 'body': '{"public":true}',
        }, source='offline_schema_fixture')
        generate([record], self.report)
        self.legacy = build_packet(self.report, ['example.test'])
        batch = self.root / 'batch'
        prepare_batch(self.report, batch, ['example.test'])
        pid = verify_batch(batch)['packets'][0]['packet_id']
        self.packet = load_json(batch / 'packets' / pid / 'packet.json')

    def test_provider_copy_changes_only_uniqueness_and_keeps_originals(self):
        for schema in (SCHEMA, SCHEMA85):
            original = copy.deepcopy(schema)
            expected = copy.deepcopy(schema)
            del expected['properties']['reviews']['items']['properties']['observation_ids']['uniqueItems']
            adapted = _provider_schema(schema)
            self.assertEqual(expected, adapted)
            self.assertEqual(original, schema)
            adapted['properties']['summary']['maxLength'] = 1
            self.assertEqual(original, schema)

    def test_schema_walk_preserves_property_names_and_literal_data(self):
        schema = {'type': 'object', 'properties': {
            'uniqueItems': {'type': 'array', 'uniqueItems': True, 'items': {'type': 'string'}},
            'data': {'enum': [{'uniqueItems': True}], 'default': {'uniqueItems': True}},
        }, '$defs': {'uniqueItems': {'type': 'array', 'uniqueItems': True}},
            'anyOf': [{'properties': {'other': {'type': 'array', 'uniqueItems': True}}}]}
        adapted = _provider_schema(schema)
        self.assertIn('uniqueItems', adapted['properties'])
        self.assertNotIn('uniqueItems', adapted['properties']['uniqueItems'])
        self.assertEqual(schema['properties']['data'], adapted['properties']['data'])
        self.assertIn('uniqueItems', adapted['$defs'])
        self.assertNotIn('uniqueItems', adapted['$defs']['uniqueItems'])
        self.assertNotIn('uniqueItems', adapted['anyOf'][0]['properties']['other'])
        self.assertTrue(schema['properties']['uniqueItems']['uniqueItems'])

    def test_duplicate_observation_ids_still_rejected_locally(self):
        for packet in (self.legacy, self.packet):
            review = {'observation_ids': [packet['evidence'][0]['observation_id']],
                'assessment': 'insufficient_evidence', 'confidence': 'low', 'reason': 'Offline fixture.',
                'evidence_notes': [], 'next_checks': [], 'report_draft': {
                    'title': '', 'impact': '', 'steps': [], 'expected': '', 'actual': '', 'remediation': ''}}
            if packet['schema_version'] == '8.5':
                review['citations'] = []
            value = {'packet_id': packet['packet_id'], 'summary': 'Offline fixture.', 'reviews': [review]}
            validate_result(value, packet)
            review['observation_ids'] *= 2
            with self.subTest(version=packet['schema_version']), self.assertRaisesRegex(ValueError, 'Duplicate result IDs'):
                validate_result(value, packet)

    def test_legacy_and_batch_share_provider_copy_with_original_packet_schema(self):
        seen = []
        def adapter(args, cwd, timeout, prompt=None, **kwargs):
            packet = json.loads(prompt.split('UNTRUSTED_EVIDENCE_JSON\n', 1)[1])
            original = SCHEMA85 if packet['schema_version'] == '8.5' else SCHEMA
            schema = load_json(Path(args[args.index('--output-schema') + 1]))
            self.assertEqual(_provider_schema(original), schema)
            self.assertNotIn('uniqueItems', schema['properties']['reviews']['items']['properties']['observation_ids'])
            self.assertTrue(original['properties']['reviews']['items']['properties']['observation_ids']['uniqueItems'])
            Path(args[args.index('-o') + 1]).write_text(json.dumps({
                'packet_id': packet['packet_id'], 'summary': 'Offline fixture.', 'reviews': []}))
            seen.append(packet['schema_version'])
            return ('{"type":"item.completed","item":{"type":"agent_message"}}\n'
                    '{"type":"turn.completed"}\n'), ''
        with patch('recon81.codex_review._configuration', return_value=[]), \
                patch('recon81.codex_review._process', side_effect=adapter):
            run_review(self.report, self.root / 'legacy', ['example.test'])
            execute_packet(self.packet)
        self.assertEqual(['8.4', '8.5'], seen)
        prepared = next((self.root / 'batch' / 'packets').glob('*/schema.json'))
        self.assertEqual(SCHEMA85, load_json(prepared))

    def test_schema_rejection_has_safe_specific_failure_code(self):
        class FailedProcess:
            stdin = io.BytesIO()
            stdout = io.BytesIO(b'{"type":"error","message":"invalid_json_schema: DO_NOT_EXPOSE_RAW_DETAIL"}\n')
            stderr = io.BytesIO()
            returncode = 1
            def wait(self, timeout=None):
                return self.returncode
        with patch('recon81.codex_review.subprocess.Popen', return_value=FailedProcess()), \
                patch('recon81.codex_review._stop'):
            with self.assertRaises(ReviewFailure) as caught:
                _process(['offline-fixture'], self.root, 10, on_event=lambda event: None)
        error = caught.exception
        self.assertEqual('OUTPUT_SCHEMA_UNSUPPORTED', error.code)
        self.assertEqual('process', error.stage)
        self.assertNotIn('DO_NOT_EXPOSE_RAW_DETAIL', str(error))
        self.assertNotIn('DO_NOT_EXPOSE_RAW_DETAIL', json.dumps(error.diagnostic))


if __name__ == '__main__':
    unittest.main()
