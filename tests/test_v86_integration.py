"""Cross-module evidence contracts exposed through the public inventory CLI."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import request_inventory
from recon81.context import attach_context
from recon81.core import normalize_record
from recon81.importers import native_record


class EvidenceIntegrationTests(unittest.TestCase):
    def record(self, path, timestamp):
        return attach_context(normalize_record(
            'https://example.test/' + path, 'GET',
            headers={'X-Workspace': 'north'}, body=b'',
            response={'status': 200, 'headers': {'Content-Type': 'application/json'}, 'body': '{"id":1}'},
            timestamp=timestamp), {'actor': 'alice', 'capture_id': 'flow', 'scenario': 'account-read'})

    def test_native_roundtrip_never_promotes_partial_bodies(self):
        record = self.record('item', '2026-10-15T01:00:00Z')
        record['body']['complete'] = False
        record['response']['body']['complete'] = False
        result = native_record(record)
        self.assertFalse(result['body']['complete'])
        self.assertFalse(result['response']['body']['complete'])
        self.assertEqual({'id': 1}, json.loads(result['response']['body']['text']))

    def test_cli_export_preserves_repeated_events_and_selector_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'capture.jsonl'
            records = [self.record('a', '2026-10-15T01:00:00Z'),
                       self.record('b', '2026-10-15T01:01:00Z'),
                       self.record('a', '2026-10-15T01:02:00Z')]
            source.write_text(''.join(json.dumps(r) + '\n' for r in records))
            db, report = root / 'inventory.db', root / 'report'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, request_inventory.main(['import', str(source), '--db', str(db),
                    '--scope', 'example.test', '--resource-header', 'X-Workspace']))
                self.assertEqual(0, request_inventory.main(['report', '--db', str(db), '--output', str(report)]))
            observations = [json.loads(line) for line in (report / 'requests.jsonl').read_text().splitlines()]
            events = [json.loads(line) for line in (report / 'capture_events.jsonl').read_text().splitlines()]
            analysis = json.loads((report / 'analysis.json').read_text())
            self.assertEqual(2, len(observations))
            self.assertEqual(3, len(events))
            self.assertTrue(all(r['resource_headers'] == ['x-workspace'] for r in observations))
            self.assertEqual(['https://example.test/a', 'https://example.test/b', 'https://example.test/a'],
                             [step['url'] for step in analysis['flows'][0]['steps']])
            manifest = json.loads((report / 'manifest.json').read_text())
            self.assertIn('capture_events.jsonl', manifest['files'])

    def test_cli_scope_filters_capture_events_and_old_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'capture.jsonl'
            records = [self.record('a', '2026-10-15T01:00:00Z'),
                       normalize_record('https://excluded.test/b', 'GET', body=b'')]
            source.write_text(''.join(json.dumps(r) + '\n' for r in records))
            db, report = root / 'inventory.db', root / 'report'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, request_inventory.main(['import', str(source), '--db', str(db),
                    '--scope', 'example.test', '--scope', 'excluded.test']))
                self.assertEqual(0, request_inventory.main(['report', '--db', str(db), '--output', str(report), '--xlsx']))
                self.assertEqual(0, request_inventory.main(['report', '--db', str(db), '--output', str(report), '--scope', 'example.test']))
            self.assertEqual(1, len((report / 'capture_events.jsonl').read_text().splitlines()))
            self.assertEqual(1, len(list((report / 'evidence').glob('*.json'))))
            self.assertFalse((report / 'request_inventory.xlsx').exists())
            self.assertNotIn('excluded.test', (report / 'requests.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
