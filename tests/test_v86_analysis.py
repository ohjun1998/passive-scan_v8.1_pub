import copy
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from examples.community_reproduce import Capture
from recon81 import analysis
from recon81.analysis import comparison_selector, comparisons, flows
from recon81.context import attach_context
from recon81.core import Inventory, MASK, canonical, normalize_record, normalize_resource_headers, redact_text
from recon81.network_policy import NetworkPolicy
from recon81.importers import native_record
from recon81.reports import postman, generate
from recon81.review_batch import prepare_batch
from request_inventory import main


def observation(actor='alice', url='https://example.test/api/orders/102', **kwargs):
    record = normalize_record(url, 'GET', body=b'', response={
        'status': 200, 'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'id': 102, 'ownerId': 'bob', 'actor': actor})}, **kwargs)
    return attach_context(record, {'actor': actor, 'scenario': 'order-view', 'capture_id': 'flow-1'})


class V86AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_signed_urls_are_masked_across_normalized_and_postman_export(self):
        for key in ('sig', 'Signature', 'X-Amz-Signature', 'X-Goog-Signature',
                    'AWSAccessKeyId', 'GoogleAccessId', 'X-Amz-Credential'):
            with self.subTest(key=key):
                secret = 'SYNTHETIC_SIGNED_URL_SECRET'
                url = 'https://example.test/blob?id=102&' + key + '=' + secret
                record = observation(url=url)
                self.assertNotIn(secret, json.dumps(record))
                self.assertNotIn(secret, json.dumps(postman([record])))
                self.assertEqual('credential_or_one_time_query', NetworkPolicy(['example.test']).reason(url))
                self.assertNotIn(secret, redact_text('saved URL: ' + url))
                self.assertIn('id=102', record['url'])

    def test_masked_selectors_never_assert_exact_resource_equivalence(self):
        a = observation(url='https://example.test/blob?sig=FIRST_SECRET')
        b = observation('bob', url='https://example.test/blob?sig=SECOND_SECRET')
        pairs, truncated = comparisons([a, b])
        self.assertEqual(0, truncated)
        self.assertEqual(1, len(pairs))
        self.assertFalse(pairs[0]['comparable'])
        self.assertTrue(pairs[0]['response_comparable'])
        self.assertEqual('unverified', pairs[0]['resource_equivalence'])
        self.assertIn('redacted_url_selector', pairs[0]['selector_uncertainty'])

    def test_masked_request_body_marks_selector_uncertain(self):
        a = normalize_record('https://example.test/api', 'POST', {'Content-Type': 'application/json'}, '{"token":"FIRST"}')
        self.assertIn('redacted_body_selector', comparison_selector(a)['uncertainty_reasons'])

    def test_configured_resource_header_preserves_all_values(self):
        a = observation(headers=[('X-Workspace', 'shared'), ('X-Workspace', 'a')])
        b = observation('bob', headers=[('X-Workspace', 'shared'), ('X-Workspace', 'b')])
        self.assertEqual(1, len(comparisons([a, b])[0]))
        self.assertEqual([], comparisons([a, b], resource_headers=['X-Workspace'])[0])
        selected = comparison_selector(a, ['X-Workspace'])
        self.assertEqual(['shared', 'a'], next(h['values'] for h in selected['headers'] if h['name'] == 'x-workspace'))
        with self.assertRaises(ValueError):
            normalize_resource_headers(['Authorization'])
        with self.assertRaises(ValueError):
            normalize_resource_headers(['X-Tenant\r\nCookie'])

    def test_report_level_resource_headers_survive_ai_preparation(self):
        a = observation(headers={'X-Workspace': 'workspace-a'})
        b = observation('bob', headers={'X-Workspace': 'workspace-b'})
        report = self.root / 'selector-report'
        generate([a, b], report, resource_headers=['X-Workspace'])
        self.assertEqual([], json.loads((report / 'analysis.json').read_text())['comparisons'])
        saved = [json.loads(line) for line in (report / 'requests.jsonl').read_text().splitlines()]
        self.assertTrue(all(r['resource_headers'] == ['x-workspace'] for r in saved))
        index = prepare_batch(report, self.root / 'selector-batch', ['example.test'])
        self.assertEqual(2, len(index['packets']))
        self.assertTrue(all(p['comparison_context']['saved_observations'] == 1 for p in index['packets']))

    def test_later_import_selector_configuration_preserves_immutable_evidence(self):
        record = observation(headers={'X-Workspace': 'workspace-a'})
        configured = copy.deepcopy(record)
        configured['resource_headers'] = ['X-Workspace']
        with Inventory(self.root / 'selector-policy.db') as inv:
            inv.add(record)
            original = inv.conn.execute('SELECT record FROM observations').fetchone()[0]
            inv.add(configured)
            self.assertEqual(original, inv.conn.execute('SELECT record FROM observations').fetchone()[0])
            self.assertEqual(['x-workspace'], list(inv.records())[0]['resource_headers'])
            self.assertEqual(1, inv.count())
        with Inventory(self.root / 'selector-policy.db') as inv:
            self.assertEqual(['x-workspace'], list(inv.records())[0]['resource_headers'])

    def test_resource_selector_metadata_contains_sanitized_values_only(self):
        record = observation(headers={'X-Workspace': 'token=SYNTHETIC_SECRET'}, resource_headers=['X-Workspace'])
        selector = comparison_selector(record)
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(selector))
        self.assertIn('redacted_header_selector', selector['uncertainty_reasons'])

    def test_response_values_parse_once_per_observation_not_per_pair(self):
        records = [observation(actor) for actor in ('alice', 'bob', 'admin', 'moderator')]
        with patch('recon81.analysis.comparison_values', wraps=analysis.comparison_values) as parse:
            pairs, _ = comparisons(records)
        self.assertEqual(6, len(pairs))
        self.assertEqual(4, parse.call_count)

    def test_capture_events_preserve_a_b_a_chronology_and_immutable_variant(self):
        a = observation(timestamp='2026-10-15T09:00:00+09:00')
        b = observation(url='https://example.test/api/orders/103', timestamp='2026-10-15T00:01:00Z')
        again = copy.deepcopy(a)
        again['timestamp'] = '2026-10-15T02:02:00+02:00'
        with Inventory(self.root / 'inventory.db') as inv:
            inv.add(a); inv.add(b); inv.add(again)
            self.assertEqual(2, inv.count())
            self.assertEqual(1, len(list(inv.records(limit=1, offset=1))))
            events = list(inv.capture_events())
            records = list(inv.records())
            persisted = json.loads(inv.conn.execute('SELECT record FROM observations WHERE id=?', (a['observation_id'],)).fetchone()[0])
            self.assertEqual(a['timestamp'], persisted['timestamp'])
        self.assertEqual([a['observation_id'], b['observation_id'], a['observation_id']], [e['observation_id'] for e in events])
        self.assertEqual('2026-10-15T00:02:00.000000+00:00', events[-1]['timestamp'])
        latest = next(r for r in records if r['observation_id'] == a['observation_id'])
        self.assertEqual(2, latest['seen_count'])
        self.assertEqual(events[-1]['timestamp'], latest['timestamp'])
        steps = flows(records, capture_events=events)[0]['steps']
        self.assertEqual([1, 2, 3], [s['event_id'] for s in steps])
        with Inventory(self.root / 'inventory.db') as inv:
            self.assertEqual(3, len(list(inv.capture_events())))
            self.assertEqual(1, len(list(inv.capture_events(limit=1, offset=2))))

    def test_old_database_migration_does_not_invent_capture_order(self):
        record = observation(timestamp='2026-10-15T09:00:00+09:00')
        path = self.root / 'legacy.db'
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE observations (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, structure_id TEXT NOT NULL, record TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER NOT NULL)')
        conn.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?)', (record['observation_id'], record['request_id'], record['structure_id'], canonical(record), record['timestamp'], record['timestamp'], 8))
        conn.commit(); conn.close()
        with Inventory(path) as inv:
            events = list(inv.capture_events())
            self.assertEqual(1, len(events))
            self.assertEqual('migrated_summary', events[0]['history_kind'])
            self.assertEqual(8, events[0]['prior_seen_count'])
        with Inventory(path) as inv:
            self.assertEqual(1, len(list(inv.capture_events())))

    def test_timestamp_quality_and_offset_sorting(self):
        record = observation(timestamp='2026-10-15T09:00:00+09:00')
        self.assertEqual('2026-10-15T00:00:00.000000+00:00', record['timestamp'])
        self.assertEqual('captured', record['timestamp_quality'])
        self.assertEqual('assumed_utc', observation(timestamp='2026-10-15T00:00:00')['timestamp_quality'])
        self.assertEqual('unparsed_ingestion_fallback', observation(timestamp='invalid timestamp')['timestamp_quality'])
        self.assertEqual('unparsed_ingestion_fallback', observation(timestamp='0001-01-01T00:00:00+14:00')['timestamp_quality'])
        # The 02:00 +02 record occurs before the 00:01 Z record.
        early = observation(timestamp='2026-10-15T02:00:00+02:00')
        late = observation(url='https://example.test/late', timestamp='2026-10-15T00:01:00Z')
        self.assertEqual(early['observation_id'], flows([late, early])[0]['steps'][0]['observation_id'])

    def test_timestamp_downgrade_survives_jsonl_roundtrip_and_events(self):
        for quality in ('ingestion_time', 'unparsed_ingestion_fallback', 'assumed_utc'):
            record = observation(timestamp='2026-10-15T00:00:00Z')
            record['timestamp_quality'] = quality
            imported = native_record(record)
            self.assertEqual(quality, imported['timestamp_quality'])
            with Inventory(self.root / (quality + '.db')) as inv:
                inv.add(imported)
                self.assertEqual(quality, list(inv.capture_events())[0]['timestamp_quality'])
        record['timestamp'] = 'invalid'
        record['timestamp_quality'] = 'captured'
        self.assertEqual('unparsed_ingestion_fallback', native_record(record)['timestamp_quality'])

    def test_probe_metadata_changes_create_immutable_variants_and_roundtrip(self):
        record = observation()
        record['probe'] = {'server': 'synthetic-server', 'tech': ['framework-a']}
        attach_context(record, record['context'])
        self.assertEqual(record['observation_id'], native_record(record)['observation_id'])
        changed = copy.deepcopy(record)
        changed['probe']['tech'] = ['framework-b']
        attach_context(changed, changed['context'])
        self.assertNotEqual(record['observation_id'], changed['observation_id'])
        with Inventory(self.root / 'probes.db') as inv:
            inv.add(record); inv.add(changed)
            self.assertEqual(2, inv.count())

    def test_cli_report_preserves_event_history_and_resource_headers(self):
        a = observation(headers={'X-Workspace': 'a'}, resource_headers=['X-Workspace'], timestamp='2026-10-15T00:00:00Z')
        b = observation('bob', headers={'X-Workspace': 'b'}, resource_headers=['X-Workspace'], timestamp='2026-10-15T00:01:00Z')
        repeated = copy.deepcopy(a)
        repeated['timestamp'] = '2026-10-15T00:02:00Z'
        source = self.root / 'captures.jsonl'
        source.write_text(''.join(json.dumps(r) + '\n' for r in (a, b, repeated)))
        db = self.root / 'cli.db'; output = self.root / 'report'
        self.assertEqual(0, main(['import', str(source), '--scope', 'example.test', '--db', str(db)]))
        self.assertEqual(0, main(['report', '--db', str(db), '--output', str(output)]))
        events = [json.loads(line) for line in (output / 'capture_events.jsonl').read_text().splitlines()]
        self.assertEqual(3, len(events))
        report = json.loads((output / 'analysis.json').read_text())
        self.assertEqual([], report['comparisons'])
        self.assertEqual(3, sum(len(flow['steps']) for flow in report['flows']))
        self.assertIn('capture_events.jsonl', json.loads((output / 'manifest.json').read_text())['files'])

    def test_known_empty_lab_get_remains_comparable(self):
        sent = []
        class Response(io.BytesIO):
            code = 200
            headers = {'Content-Type': 'application/json'}
        class Opener:
            def open(self, request, timeout):
                sent.append(request.data)
                return Response(b'{"id":102,"ownerId":"bob"}')
        capture = Capture('http://127.0.0.1:18090', self.root / 'lab', 'synthetic-password')
        capture.clients['alice'] = Opener()
        capture.clients['bob'] = Opener()
        capture.request('alice', '/api/vuln/orders/102', 'orders', 'deny')
        capture.request('bob', '/api/vuln/orders/102', 'orders', 'allow')
        self.assertEqual([None, None], sent)
        self.assertTrue(all(r['body']['complete'] and r['body']['kind'] == 'empty' for r in capture.records))
        pairs, _ = comparisons(capture.records)
        self.assertEqual(1, len(pairs))
        self.assertTrue(pairs[0]['comparable'])

    def test_capture_event_changes_roll_back_with_failed_import(self):
        path = self.root / 'rollback.db'
        with self.assertRaises(ValueError):
            with Inventory(path) as inv:
                inv.add(observation())
                raise ValueError('bad later record')
        with Inventory(path) as inv:
            self.assertEqual(0, inv.count())
            self.assertEqual([], list(inv.capture_events()))


if __name__ == '__main__':
    unittest.main()
