"""Offline cache, discovery and report integrity regressions for v8.6."""
import hashlib
import json
import os
import errno
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from recon81.assets import AssetCache, cache_db_path, entries, reusable, reuse_analysis, update_analysis, write_entries
from recon81.core import normalize_record
from recon81.discovery import openapi_records
from recon81.importers import js_record
from recon81.reports import generate


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.url = 'https://example.test/main.js'
        self.key = hashlib.sha256(self.url.encode()).hexdigest()
        self.cache = self.root/'cache.jsonl'

    def tearDown(self): self.temp.cleanup()

    def metadata(self):
        return {'url_hash':self.key,'url':self.url,'downloaded_at':1000,'content_hash':'a'*64}

    def records(self, count):
        return [js_record({'url':'https://example.test/api/'+str(i),'method':'GET'},self.url) for i in range(count)]

    def test_full_extract_survives_indexed_reuse_and_export(self):
        with AssetCache(self.cache) as store: store.put_download(self.metadata())
        self.assertFalse(self.cache.exists())
        original = update_analysis(self.cache,self.key,'a'*64,'tool-v1',self.records(501))
        mapping=self.root/'mapping'; mapping.write_text(self.key+'.js\t'+self.url+'\n')
        reused=reuse_analysis(self.cache,mapping,'tool-v1')
        self.assertEqual(501,len(reused))
        self.assertEqual({r['observation_id'] for r in original},{r['observation_id'] for r in reused})
        export=self.root/'export.jsonl'; write_entries(export,entries(self.cache))
        self.assertEqual(501,len(entries(export)[self.key]['analysis']['records']))
        self.assertTrue(reusable(entries(export)[self.key],'tool-v1'))

    def test_partial_legacy_cache_is_never_reusable(self):
        item=self.metadata(); item['analysis']={'content_hash':'a'*64,'analyzer_version':'tool-v1','records':self.records(2),'total_records':501}
        self.cache.write_text(json.dumps(item)+'\n')
        clean=entries(self.cache)[self.key]
        self.assertFalse(clean['analysis']['complete'])
        self.assertFalse(reusable(clean,'tool-v1'))
        result=update_analysis(self.cache,self.key,'a'*64,'tool-v1',self.records(501))
        self.assertTrue(result[0]['asset']['delta_partial'])
        self.assertTrue(reusable(entries(self.cache)[self.key],'tool-v1'))

    def test_download_metadata_update_does_not_read_or_replace_extracts(self):
        with AssetCache(self.cache) as store: store.put_download(self.metadata())
        update_analysis(self.cache,self.key,'a'*64,'tool-v1',self.records(3))
        with AssetCache(self.cache) as store:
            statements=[]; store.conn.set_trace_callback(statements.append)
            newer=dict(self.metadata(),downloaded_at=2000)
            store.put_download(newer)
            self.assertFalse(any('asset_records' in statement for statement in statements))
            self.assertEqual(3,len(store.get(self.key)['analysis']['records']))
        self.assertFalse(self.cache.exists())

    def test_legacy_import_is_once_and_newer_index_is_preserved(self):
        self.cache.write_text(json.dumps(self.metadata())+'\n')
        with AssetCache(self.cache) as store: store.put_download(dict(self.metadata(),downloaded_at=2000))
        with patch('recon81.assets._legacy_lines',side_effect=AssertionError('legacy file reread')):
            with AssetCache(self.cache) as store:
                self.assertEqual(2000,store.get(self.key)['downloaded_at'])
        self.assertEqual(0o600,cache_db_path(self.cache).stat().st_mode & 0o777)

    def test_touching_equal_timestamp_legacy_does_not_downgrade_complete_extract(self):
        item=self.metadata(); item['analysis']={'content_hash':'a'*64,'analyzer_version':'tool-v1','records':self.records(1),'total_records':501}
        self.cache.write_text(json.dumps(item)+'\n')
        entries(self.cache)
        update_analysis(self.cache,self.key,'a'*64,'tool-v1',self.records(501))
        stat=self.cache.stat(); os.utime(self.cache,ns=(stat.st_atime_ns,stat.st_mtime_ns+1000000))
        current=entries(self.cache)[self.key]
        self.assertEqual(501,len(current['analysis']['records']))
        self.assertTrue(reusable(current,'tool-v1'))

    def test_report_regeneration_removes_owned_stale_files_preserves_unrelated(self):
        a=normalize_record('https://a.test/','GET',body=b''); b=normalize_record('https://b.test/private','GET',body=b'')
        out=self.root/'report'; generate([a,b],out,xlsx=True)
        (out/'notes.txt').write_text('user notes')
        (out/'evidence'/'manual.txt').write_text('user evidence')
        generate([a],out)
        self.assertFalse((out/'evidence'/(b['observation_id']+'.json')).exists())
        self.assertFalse((out/'request_inventory.xlsx').exists())
        self.assertEqual('user notes',(out/'notes.txt').read_text())
        self.assertEqual('user evidence',(out/'evidence'/'manual.txt').read_text())
        manifest=json.loads((out/'manifest.json').read_text())
        self.assertIn('index.html',manifest['files'])
        self.assertNotIn('notes.txt',manifest['files'])
        for name,expected in manifest['files'].items():
            self.assertEqual(expected,hashlib.sha256((out/name).read_bytes()).hexdigest())

    def test_report_refuses_unowned_collision_and_keeps_prior_generation_on_failure(self):
        r=normalize_record('https://example.test/','GET',body=b''); out=self.root/'report'
        out.mkdir(); (out/'index.html').write_text('user page')
        with self.assertRaises(ValueError): generate([r],out)
        self.assertEqual('user page',(out/'index.html').read_text())
        (out/'index.html').unlink(); generate([r],out)
        before={str(p.relative_to(out)):p.read_bytes() for p in out.rglob('*') if p.is_file()}
        with patch('openpyxl.workbook.workbook.Workbook.save',side_effect=OSError('fixture failure')):
            with self.assertRaises(OSError): generate([],out,xlsx=True)
        self.assertEqual(before,{str(p.relative_to(out)):p.read_bytes() for p in out.rglob('*') if p.is_file()})
        self.assertFalse(list(self.root.glob('.report-stage-*')))

    def test_partitioned_html_preserves_full_evidence_and_bound_receipts(self):
        records=[normalize_record('https://example.test/'+str(i),'GET',body=b'') for i in range(5)]
        out=self.root/'report'
        with patch('recon81.reports.DASHBOARD_MAX_RECORDS',2): generate(records,out,capture_events=[])
        self.assertEqual(3,len(list((out/'pages').glob('requests-*.html'))))
        self.assertEqual(5,len((out/'requests.jsonl').read_text().splitlines()))
        manifest=json.loads((out/'manifest.json').read_text())
        self.assertIn('capture_events.jsonl',manifest['files'])
        self.assertIn('pages/requests-3.html',manifest['files'])
        self.assertIn('searchIndex',(out/'pages'/'requests-1.html').read_text())
        generate(records[:1],out)
        self.assertFalse(list((out/'pages').glob('*.html')))

    def test_verified_legacy_report_is_adopted_and_stale_evidence_removed(self):
        a=normalize_record('https://a.test/','GET',body=b''); b=normalize_record('https://b.test/','GET',body=b'')
        out=self.root/'report'; generate([a,b],out)
        manifest=json.loads((out/'manifest.json').read_text())
        (out/'manifest.json').write_text(json.dumps({'schema_version':'8.4','files':{name:manifest['files'][name] for name in ('requests.jsonl','analysis.json')}}))
        generate([a],out)
        self.assertFalse((out/'evidence'/(b['observation_id']+'.json')).exists())

    def test_report_writer_lock_rejects_concurrent_generation(self):
        if os.name=='nt': self.skipTest('POSIX lock integration; Windows branch is mocked separately')
        import fcntl
        out=self.root/'report'; lock=self.root/'.report.report.lock'
        with open(lock,'w') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError,'already in progress'): generate([],out)
        self.assertFalse(out.exists())

    def test_windows_report_lock_uses_nonblocking_byte_lock_and_maps_contention(self):
        from recon81.reports import _acquire_report_lock
        windows=Mock(LK_NBLCK=2)
        with open(self.root/'windows-lock','w+b') as stream:
            with patch.dict(sys.modules,{'msvcrt':windows}),patch('recon81.reports.os.name','nt'):
                _acquire_report_lock(stream.fileno())
                windows.locking.assert_called_once_with(stream.fileno(),2,1)
                self.assertEqual(1,os.fstat(stream.fileno()).st_size)
                self.assertEqual(0,os.lseek(stream.fileno(),0,os.SEEK_CUR))
                windows.locking.side_effect=OSError(errno.EACCES,'locked')
                with self.assertRaisesRegex(ValueError,'already in progress'):
                    _acquire_report_lock(stream.fileno())

    def test_failed_publication_and_restore_preserve_backup_for_next_run(self):
        out=self.root/'report'; generate([],out); (out/'notes.txt').write_text('keep me')
        original=os.replace
        def fail_directory_publish(source,destination):
            source=Path(source); destination=Path(destination)
            if destination==out and source.name.startswith(('.report-stage-','.report-backup-')):
                raise OSError('fixture filesystem failure')
            return original(source,destination)
        with patch('recon81.reports.os.replace',side_effect=fail_directory_publish):
            with self.assertRaises(OSError): generate([],out)
        backups=list(self.root.glob('.report-backup-*'))
        self.assertEqual(1,len(backups)); self.assertEqual('keep me',(backups[0]/'notes.txt').read_text())
        self.assertTrue((self.root/'.report.report-journal.json').exists())
        generate([],out)
        self.assertEqual('keep me',(out/'notes.txt').read_text())
        self.assertFalse(list(self.root.glob('.report-backup-*')))
        self.assertFalse((self.root/'.report.report-journal.json').exists())

    def test_oversized_single_observation_links_complete_evidence_with_small_html(self):
        record=normalize_record('https://example.test/','POST',{'Content-Type':'application/json'},json.dumps({'data':'x'*40000}))
        out=self.root/'report'
        with patch('recon81.reports.DASHBOARD_MAX_BYTES',32768): generate([record],out)
        page=out/'pages'/'requests-1.html'
        self.assertLess(page.stat().st_size,32768)
        self.assertIn(record['observation_id'],page.read_text())
        self.assertIn('x'*40000,(out/'evidence'/(record['observation_id']+'.json')).read_text())


class DiscoveryBudgetTests(unittest.TestCase):
    def document(self, schemas, root):
        return {'openapi':'3.0.0','servers':[{'url':'https://example.test'}],'components':{'schemas':schemas},'paths':{'/x':{'post':{'requestBody':{'content':{'application/json':{'schema':{'$ref':'#/components/schemas/'+root}}}},'responses':{}}}}}

    def test_shared_reference_dag_has_bounded_work_and_no_duplicate_fields(self):
        schemas={'S0':{'type':'object','properties':{'id':{'type':'integer'}}}}
        for n in range(1,8): schemas['S'+str(n)]={'allOf':[{'$ref':'#/components/schemas/S'+str(n-1)} for _ in range(20)]}
        r=list(openapi_records(json.dumps(self.document(schemas,'S7')).encode()))[0]
        self.assertEqual(['$.id'],r['body']['fields'])
        self.assertLess(r['schema']['schema_nodes_visited'],40)
        self.assertTrue(r['schema']['complete'])

    def test_depth_cycles_and_property_truncation_are_explicit(self):
        schemas={'Loop':{'type':'object','properties':{'next':{'$ref':'#/components/schemas/Loop'}}}}
        r=list(openapi_records(json.dumps(self.document(schemas,'Loop')).encode()))[0]
        self.assertFalse(r['schema']['complete']); self.assertIn('schema_cycle',r['schema']['omissions'])
        schemas={'Large':{'type':'object','properties':{'f'+str(n):{'type':'string'} for n in range(201)}}}
        r=list(openapi_records(json.dumps(self.document(schemas,'Large')).encode()))[0]
        self.assertEqual(200,len(r['body']['fields'])); self.assertIn('schema_property_limit',r['schema']['omissions'])

    def test_document_work_budget_remains_bounded_across_many_operations(self):
        doc=self.document({'Base':{'type':'object','properties':{'id':{'type':'integer'}}}},'Base')
        for i in range(70):
            doc['paths']['/x'+str(i)]={'post':{'requestBody':{'content':{'application/json':{'schema':{'type':'object','properties':{'f'+str(n):{'type':'string'} for n in range(200)}}}}},'responses':{}}}
        records=list(openapi_records(json.dumps(doc).encode()))
        self.assertLessEqual(sum(r['schema']['schema_nodes_visited'] for r in records),12000)
        self.assertTrue(any('schema_node_budget' in r['schema']['omissions'] for r in records))


if __name__=='__main__': unittest.main()
