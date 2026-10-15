"""Provider schema compatibility with the original local result contract intact."""
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon81.ai_review import SCHEMA, build_packet, load_json, validate_result
from recon81.codex_review import ReviewFailure, _process, _provider_schema, execute_packet, make_prompt, run_review
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

    def test_provider_binds_only_the_supplied_packet_ids_without_mutating_inputs(self):
        packet = {'packet_id': 'a' * 64, 'evidence': [
            {'observation_id': 'c' * 64}, {'observation_id': 'b' * 64},
        ]}
        for schema in (SCHEMA, SCHEMA85):
            original_schema, original_packet = copy.deepcopy(schema), copy.deepcopy(packet)
            adapted = _provider_schema(schema, packet)
            self.assertEqual([packet['packet_id']], adapted['properties']['packet_id']['enum'])
            properties = adapted['properties']['reviews']['items']['properties']
            self.assertEqual(['b' * 64, 'c' * 64], properties['observation_ids']['items']['enum'])
            if 'citations' in properties:
                citation = properties['citations']['items']['properties']['observation_id']
                self.assertEqual(['b' * 64, 'c' * 64], citation['enum'])
                # Each enum owns its own list; adapting one field cannot change another.
                citation['enum'].append('d' * 64)
                self.assertNotIn('d' * 64, properties['observation_ids']['items']['enum'])
            self.assertEqual(original_schema, schema)
            self.assertEqual(original_packet, packet)
            self.assertNotIn('enum', _provider_schema(schema)['properties']['packet_id'])

    def test_large_legacy_packet_keeps_valid_provider_enum_budget(self):
        for count in (250, 251):
            packet = {'packet_id': 'a' * 64, 'evidence': [
                {'observation_id': format(index, '064x')} for index in range(count)
            ]}
            for schema in (SCHEMA, SCHEMA85):
                with self.subTest(count=count, citations=schema is SCHEMA85):
                    adapted = _provider_schema(schema, packet)
                    self.assertEqual([packet['packet_id']], adapted['properties']['packet_id']['enum'])
                    properties = adapted['properties']['reviews']['items']['properties']
                    item = properties['observation_ids']['items']
                    self.assertEqual(count == 250, 'enum' in item)
                    self.assertEqual(SCHEMA['properties']['reviews']['items']['properties']['observation_ids']['items']['pattern'],
                                     item['pattern'])
                    if 'citations' in properties:
                        citation = properties['citations']['items']['properties']['observation_id']
                        self.assertEqual(count == 250, 'enum' in citation)

    def test_citation_prompt_states_membership_exact_values_and_empty_evidence_contract(self):
        prompt = make_prompt(self.packet)
        instructions, payload = prompt.split('UNTRUSTED_EVIDENCE_JSON\n', 1)
        self.assertEqual(self.packet, json.loads(payload))
        self.assertRegex(instructions, r'packet_id.*observation_id.*그대로 복사')
        self.assertRegex(instructions, r'citations\[\]\.observation_id.*해당 의견의 observation_ids.*이 패킷의 evidence.*모두 포함')
        for contract in ('JSON 따옴표 없이 실제 문자열 값', 'canonical JSON', '/0/value',
                         '헤더 이름과 값을 합친 문장이나 의역', 'insufficient_evidence 의견',
                         'citations: []', '인용을 만들어 내지 마세요'):
            self.assertIn(contract, instructions)
        self.assertNotIn('citations: []', make_prompt(self.legacy).split('UNTRUSTED_EVIDENCE_JSON\n', 1)[0])

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
            self.assertEqual(_provider_schema(original, packet), schema)
            self.assertEqual([packet['packet_id']], schema['properties']['packet_id']['enum'])
            properties = schema['properties']['reviews']['items']['properties']
            self.assertEqual(sorted(record['observation_id'] for record in packet['evidence']),
                             properties['observation_ids']['items']['enum'])
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
