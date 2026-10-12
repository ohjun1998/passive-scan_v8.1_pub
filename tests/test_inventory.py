import base64
import gzip
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from recon81.core import (MASK, Inventory, Scope, normalize_record, normalize_body,
                          safe_url, packet, xml_root, MAX_BODY)
from recon81.importers import load_records, js_record, har_entry, native_record
from recon81.reports import generate, postman
from record_browser import record_request
from request_inventory import main


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.headers = {'Content-Type': 'application/json'}

    def tearDown(self):
        self.temp.cleanup()

    def record(self, method='POST', body='{"userId":123}', **kwargs):
        return normalize_record('https://example.test/api/profile', method, self.headers, body, **kwargs)

    def test_exact_scope_and_subdomains(self):
        exact = Scope(['example.test'])
        wild = Scope(['*.example.test'])
        self.assertTrue(exact.allows('https://example.test:8443/a'))
        self.assertFalse(exact.allows('https://api.example.test/a'))
        self.assertTrue(wild.allows('https://api.example.test/a'))
        self.assertFalse(wild.allows('https://example.test.attacker.test/'))
        self.assertFalse(wild.allows('https://badexample.test/'))
        self.assertFalse(exact.allows('https://user:pass@example.test/'))
        self.assertFalse(exact.allows('javascript:alert(1)'))
        self.assertFalse(exact.allows('https://example.test:invalid/'))

    def test_query_tokens_masked_duplicate_keys_preserved(self):
        url = safe_url('https://example.test/a?id=1&id=2&token=MYSECRET#password=x')
        self.assertNotIn('MYSECRET', url)
        self.assertIn('id=1&id=2', url)
        self.assertNotIn('#', url)

    def test_nested_secrets_and_auth_headers(self):
        r = normalize_record('https://example.test/a', 'POST', {'Content-Type': 'application/json', 'Authorization': 'Bearer NEVER_SAVE_THIS', 'Cookie': 'session=NEVER_SAVE_THIS'}, '{"userId":123,"auth":{"password":"NEVER_SAVE_THIS","refreshToken":"NEVER_SAVE_THIS"}}', {'status':200,'headers':{'Content-Type':'application/json','Set-Cookie':'session=NEVER_SAVE_THIS'},'body':'{"access_token":"NEVER_SAVE_THIS","ok":true}'})
        self.assertNotIn('NEVER_SAVE_THIS', json.dumps(r))
        self.assertIn('123', r['body']['text'])

    def test_json_arrays_have_nested_fields(self):
        body = normalize_body(b'{"users":[{"id":1,"role":"user"}]}', 'application/json')
        self.assertIn('$.users[].id', body['fields'])
        self.assertIn('$.users[].role', body['fields'])

    def test_form_duplicate_fields_and_empty_values(self):
        b = normalize_body(b'id=1&id=2&empty=&password=SECRET', 'application/x-www-form-urlencoded')
        self.assertTrue(b['text'].startswith('id=1&id=2&empty='))
        self.assertNotIn('SECRET', b['text'])

    def test_xml_body_secrets(self):
        b = normalize_body(b'<Envelope><AuthInfo><Password>SECRET</Password></AuthInfo><id>123</id></Envelope>', 'text/xml')
        self.assertEqual('xml', b['kind'])
        self.assertNotIn('SECRET', b['text'])
        self.assertIn('123', b['text'])

    def test_xml_entities_rejected(self):
        payload = '<!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/passwd">]><x>&xx;</x>'
        self.assertEqual('omitted', normalize_body(payload, 'text/xml')['kind'])
        with self.assertRaises(ValueError):
            xml_root(payload, allow_burp_dtd=True)

    def test_utf16_xml_entities_rejected(self):
        payload = '<!DOCTYPE x [<!ENTITY xx "danger">]><x>&xx;</x>'.encode('utf-16')
        with self.assertRaises(ValueError):
            xml_root(payload, allow_burp_dtd=True)

    def test_burp_standard_safe_dtd(self):
        request = base64.b64encode(b'POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"id":1}').decode()
        response = base64.b64encode(b'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"ok":true}').decode()
        p = self.root/'burp.xml'
        p.write_text('<!DOCTYPE items [<!ELEMENT items (item*)><!ELEMENT item ANY>]><items><item><url>https://example.test/api</url><request base64="true">'+request+'</request><response base64="true">'+response+'</response></item></items>')
        record = list(load_records(p))[0]
        self.assertEqual('POST', record['method'])
        self.assertEqual(201, record['response']['status'])
        self.assertIn('1', record['body']['text'])

    def test_burp_plain_xml_requests(self):
        p = self.root/'burp.xml'
        p.write_text('<items><item><url>https://example.test/api</url><request base64="false"><![CDATA[POST /api HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nid=1&password=SECRET]]></request></item></items>')
        r = list(load_records(p))[0]
        self.assertNotIn('SECRET', r['body']['text'])
        self.assertEqual('form', r['body']['kind'])

    def test_multipart_file_metadata_no_bytes(self):
        data = b'--X\r\nContent-Disposition: form-data; name="id"\r\n\r\n123\r\n--X\r\nContent-Disposition: form-data; name="token"\r\n\r\nSECRET\r\n--X\r\nContent-Disposition: form-data; name="file"; filename="demo.png"\r\nContent-Type: image/png\r\n\r\nBINARY_SECRET\r\n--X--\r\n'
        b = normalize_body(data, 'multipart/form-data; boundary=X')
        self.assertEqual('multipart', b['kind'])
        self.assertEqual(['file','id','token'], b['fields'])
        self.assertNotIn('SECRET', b['text'])
        self.assertIn('demo.png', b['text'])
        self.assertFalse(b['complete'])

    def test_body_size_limit_omits_without_partial_secret(self):
        b = normalize_body(b'A'*(MAX_BODY+1), 'application/json')
        self.assertEqual('body_size_limit', b['reason'])
        self.assertEqual('', b['text'])

    def test_unstructured_body_defaults_to_omitted(self):
        self.assertEqual('omitted', normalize_body(b'SECRET', 'text/plain')['kind'])
        self.assertEqual('text', normalize_body(b'hello', 'text/plain', True)['kind'])

    def test_malformed_json_does_not_fall_back_to_raw(self):
        b = normalize_body(b'{"password":"SECRET', 'application/json', True)
        self.assertEqual('omitted', b['kind'])
        self.assertNotIn('SECRET', b['text'])

    def test_invalid_binary_omitted(self):
        self.assertEqual('omitted', normalize_body(b'\xff\x00', 'application/octet-stream')['kind'])

    def test_gzip_packet(self):
        first, h, body = packet(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n'+gzip.compress(b'{"id":123}'))
        self.assertEqual(b'{"id":123}', body)

    def test_chunked_packet(self):
        first, h, body = packet(b'POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nid=1\r\n0\r\n\r\n')
        self.assertEqual(b'id=1', body)

    def test_malformed_chunked_body_omitted(self):
        self.assertIsNone(packet(b'POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nid=1XX')[2])

    def test_incomplete_chunked_body_is_not_marked_complete(self):
        self.assertIsNone(packet(b'POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nid=1\r\n')[2])

    def test_method_and_values_separate_but_structure_grouped(self):
        a = self.record()
        b = self.record(body='{"userId":124}')
        c = self.record(method='PUT')
        d = normalize_record('https://example.test/api/profile', 'POST', self.headers, '{"userId":123,"role":"admin"}')
        self.assertEqual(a['structure_id'], b['structure_id'])
        self.assertNotEqual(a['request_id'], b['request_id'])
        self.assertNotEqual(a['structure_id'], c['structure_id'])
        self.assertNotEqual(a['structure_id'], d['structure_id'])

    def test_different_paths_never_collapsed(self):
        a = normalize_record('https://example.test/api/a', 'GET', body=b'')
        b = normalize_record('https://example.test/api/b', 'GET', body=b'')
        self.assertNotEqual(a['structure_id'], b['structure_id'])

    def test_db_idempotence_with_response_variants(self):
        db = self.root/'inventory.db'
        a = self.record(response={'status':200,'body':b''})
        b = self.record(response={'status':403,'body':b''})
        with Inventory(db) as inv:
            inv.add(a); inv.add(a); inv.add(b)
        with Inventory(db) as inv:
            records = list(inv.records())
        self.assertEqual(2, len(records))
        self.assertEqual([1,2], sorted(r['seen_count'] for r in records))
        self.assertEqual(1, len({r['request_id'] for r in records}))

    def test_har_response_base64_and_post_form_params(self):
        r = har_entry({'request':{'url':'https://example.test/a','method':'POST','postData':{'mimeType':'application/x-www-form-urlencoded','params':[{'name':'id','value':'1'}]}},'response':{'status':200,'content':{'mimeType':'application/json','encoding':'base64','text':base64.b64encode(b'{"ok":true}').decode()}}})
        self.assertEqual('id=1', r['body']['text'])
        self.assertIn('true', r['response']['body']['text'])

    def test_har_missing_payload_distinguished_from_empty(self):
        r = har_entry({'request':{'url':'https://example.test/a','method':'POST'}})
        self.assertFalse(r['body']['complete'])
        self.assertEqual('body_not_captured', r['body']['reason'])

    def test_static_js_relative_resolution_and_no_invented_values(self):
        r = js_record({'url':'/api/profile','method':'PUT','bodyParams':['id'], 'headers':{'Authorization':'SECRET'}}, 'https://example.test/static/main.js')
        self.assertEqual('https://example.test/api/profile', r['url'])
        self.assertFalse(r['observed'])
        self.assertEqual('', r['body']['text'])
        self.assertEqual(['id'], r['body']['fields'])
        self.assertNotIn('SECRET', json.dumps(r))

    def test_unknown_method_is_unknown(self):
        self.assertEqual('UNKNOWN', js_record({'url':'https://example.test/a'})['method'])

    def test_relative_js_without_base_fails(self):
        with self.assertRaises(ValueError):
            js_record({'url':'/api/profile'})

    def test_native_import_rechecks_secrets(self):
        r = self.record()
        r['body']['text'] = '{"password":"SECRET","userId":1}'
        r['headers'].append({'name':'Cookie','value':'SECRET'})
        clean = native_record(r)
        self.assertNotIn('SECRET', json.dumps(clean))

    def test_native_static_metadata_survives(self):
        r = js_record({'url':'https://example.test/a','bodyParams':['id']})
        self.assertEqual(['id'], native_record(r)['body']['fields'])
        self.assertFalse(native_record(r)['observed'])

    def test_cli_scope_filters_without_network(self):
        p = self.root/'urls.txt'
        p.write_text('https://example.test/a\nhttps://outside.test/a\n')
        db = self.root/'inventory.db'
        with patch('urllib.request.urlopen', side_effect=AssertionError('No network allowed')):
            self.assertEqual(0, main(['import',str(p),'--scope','example.test','--db',str(db)]))
        with Inventory(db) as inv:
            self.assertEqual(1, len(list(inv.records())))

    def test_import_rolls_back_entire_batch_on_bad_file(self):
        good = self.root/'good.txt'; good.write_text('https://example.test/a\n')
        bad = self.root/'bad.jsonl'; bad.write_text('not json')
        db = self.root/'inventory.db'
        self.assertEqual(2, main(['import',str(good),str(bad),'--scope','example.test','--db',str(db)]))
        with Inventory(db) as inv:
            self.assertEqual([], list(inv.records()))

    def test_report_escapes_script_payload(self):
        r = self.record(body=json.dumps({'nickname':'</script><script>alert(1)</script>'}))
        with Inventory(self.root/'inventory.db') as inv:
            inv.add(r); inv.conn.commit(); records = list(inv.records())
        output = self.root/'report'
        generate(records, output, True)
        html = (output/'index.html').read_text()
        self.assertNotIn('</script><script>alert(1)</script>', html)
        self.assertIn('textContent', html)
        self.assertTrue((output/'request_inventory.xlsx').exists())
        self.assertEqual(1, len(list((output/'evidence').glob('*.json'))))

    def test_excel_formula_injection_protection(self):
        from openpyxl import load_workbook
        r = self.record(body='{"id":1}', source='=HYPERLINK("https://evil.test")')
        with Inventory(self.root/'inventory.db') as inv:
            inv.add(r); inv.conn.commit(); records = list(inv.records())
        generate(records,self.root/'report',True)
        wb = load_workbook(self.root/'report'/'request_inventory.xlsx')
        self.assertNotEqual('f',wb['Requests v8.1']['H2'].data_type)

    def test_postman_preserves_method_body_and_blocks_execution(self):
        p = postman([self.record(method='PUT')])
        self.assertEqual('PUT',p['item'][0]['request']['method'])
        self.assertIn('123',p['item'][0]['request']['body']['raw'])
        self.assertIn('throw new Error',p['event'][0]['script']['exec'][0])

    def test_browser_adapter_actual_body(self):
        class Request:
            url='https://example.test/a'; method='PATCH'; headers={'Content-Type':'application/json','Authorization':'SECRET'}; post_data_buffer=b'{"userId":1,"password":"SECRET"}'
        class Response:
            status=200; headers={'Content-Type':'application/json','Content-Length':'11'}
            def body(self): return b'{"ok":true}'
        r = record_request(Request(),Response())
        self.assertEqual('PATCH',r['method'])
        self.assertNotIn('SECRET',json.dumps(r))
        self.assertEqual('json',r['response']['body']['kind'])

    def test_browser_adapter_does_not_read_unbounded_response(self):
        class Request:
            url='https://example.test/a'; method='GET'; headers={}; post_data_buffer=None
        class Response:
            status=200; headers={'Content-Type':'application/json'}
            def body(self): raise AssertionError('Unbounded read')
        r=record_request(Request(),Response())
        self.assertFalse(r['response']['body']['complete'])


if __name__ == '__main__':
    unittest.main()
