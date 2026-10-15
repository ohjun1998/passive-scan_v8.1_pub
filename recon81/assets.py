"""Indexed private JS cache; complete extracts are separate from bounded previews.

Legacy JSONL paths remain import/export boundaries. Their ``.sqlite3`` sibling is
now authoritative for incremental updates; modified legacy files are merged once.
"""
import hashlib
import json
import math
import os
import re
import sqlite3
from pathlib import Path
from .core import MAX_FILE, private_write, safe_url, redact_text, canonical
from .context import attach_context
from .importers import native_record


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def cache_db_path(path):
    path = Path(path)
    return path if path.suffix in ('.sqlite3', '.sqlite', '.db') else Path(str(path) + '.sqlite3')


def _legacy_lines(path):
    """Migrate large snapshots incrementally, while bounding each asset record."""
    with open(path,'rb') as stream:
        while True:
            line=stream.readline(MAX_FILE+1)
            if not line: return
            if len(line)>MAX_FILE: raise ValueError('Legacy asset entry exceeds size limit')
            yield line


def sanitize_entry(item):
    if not isinstance(item, dict) or not re.fullmatch('[0-9a-f]{64}', str(item.get('url_hash', ''))):
        raise ValueError('Invalid asset key')
    result = {'url_hash': item['url_hash'], 'url': safe_url(item['url']), 'downloaded_at': float(item['downloaded_at'])}
    if not math.isfinite(result['downloaded_at']):
        raise ValueError('Invalid asset timestamp')
    if re.fullmatch('[0-9a-f]{64}', str(item.get('content_hash', ''))):
        result['content_hash'] = item['content_hash']
    for key in ('etag', 'last_modified'):
        value = str(item.get(key, ''))
        if value and len(value) <= 256 and '\r' not in value and '\n' not in value:
            result[key] = redact_text(value)
    analysis = item.get('analysis')
    if isinstance(analysis, dict) and re.fullmatch('[0-9a-f]{64}', str(analysis.get('content_hash', ''))) and isinstance(analysis.get('records'), list):
        records = [native_record(dict(r, observed=False, source='jsluice', origin_url=result['url'], response=None, context={})) for r in analysis['records']]
        total = max(len(records), int(analysis.get('total_records', len(records))))
        result['analysis'] = {'content_hash': analysis['content_hash'], 'analyzer_version': redact_text(str(analysis.get('analyzer_version', '')))[:128],
                              'records': records, 'total_records': total, 'record_count': len(records), 'complete': total == len(records)}
    return result


class AssetCache:
    """One indexed transaction per changed asset; never rewrites unrelated extracts."""
    def __init__(self, path):
        self.legacy = Path(path)
        self.path = cache_db_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError('Cache must not be a symlink')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.execute('CREATE TABLE IF NOT EXISTS assets (url_hash TEXT PRIMARY KEY, downloaded_at REAL NOT NULL, metadata TEXT NOT NULL)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS asset_freshness ON assets(downloaded_at)')
        self.conn.execute('CREATE TABLE IF NOT EXISTS asset_records (url_hash TEXT NOT NULL REFERENCES assets(url_hash) ON DELETE CASCADE, position INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(url_hash,position))')
        self.conn.execute('CREATE TABLE IF NOT EXISTS cache_imports (path TEXT PRIMARY KEY, stamp TEXT NOT NULL)')
        try:
            self._import_legacy()
        except BaseException:
            self.conn.close()
            raise

    def _import_legacy(self):
        if self.legacy == self.path or not self.legacy.exists():
            return
        stat = self.legacy.stat()
        stamp = str(stat.st_mtime_ns) + ':' + str(stat.st_size)
        name = str(self.legacy.resolve())
        previous = self.conn.execute('SELECT stamp FROM cache_imports WHERE path=?', (name,)).fetchone()
        if previous and previous[0] == stamp:
            return
        with self.conn:
            for line in _legacy_lines(self.legacy):
                try:
                    item = sanitize_entry(json.loads(line))
                    old = self.conn.execute('SELECT downloaded_at FROM assets WHERE url_hash=?', (item['url_hash'],)).fetchone()
                    if not old or item['downloaded_at'] > old[0]:
                        self._put(item)
                except (ValueError, KeyError, TypeError):
                    continue
            self.conn.execute('INSERT OR REPLACE INTO cache_imports VALUES (?,?)', (name, stamp))

    def get(self, key, include_records=True):
        row = self.conn.execute('SELECT metadata FROM assets WHERE url_hash=?', (key,)).fetchone()
        if not row:
            return None
        result = json.loads(row[0])
        if include_records and 'analysis' in result:
            result['analysis']['records'] = [json.loads(row[0]) for row in self.conn.execute('SELECT record FROM asset_records WHERE url_hash=? ORDER BY position', (key,))]
        return result

    def keys(self):
        return [row[0] for row in self.conn.execute('SELECT url_hash FROM assets ORDER BY url_hash')]

    def fresh_keys(self, timestamp, ttl=7*86400):
        return {row[0] for row in self.conn.execute('SELECT url_hash FROM assets WHERE downloaded_at<=? AND downloaded_at>?', (timestamp, timestamp-ttl))}

    def _put(self, item):
        item = dict(item)
        analysis = item.get('analysis')
        records = None
        if analysis is not None:
            analysis = dict(analysis)
            records = analysis.pop('records', None)
            item['analysis'] = analysis
        self.conn.execute('INSERT INTO assets VALUES (?,?,?) ON CONFLICT(url_hash) DO UPDATE SET downloaded_at=excluded.downloaded_at,metadata=excluded.metadata', (item['url_hash'], item['downloaded_at'], canonical(item)))
        if records is not None:
            self.conn.execute('DELETE FROM asset_records WHERE url_hash=?', (item['url_hash'],))
            self.conn.executemany('INSERT INTO asset_records VALUES (?,?,?)', ((item['url_hash'], i, canonical(r)) for i, r in enumerate(records)))
        elif analysis is None:
            self.conn.execute('DELETE FROM asset_records WHERE url_hash=?', (item['url_hash'],))

    def put(self, item):
        clean = sanitize_entry(item)
        with self.conn:
            self._put(clean)

    def put_download(self, item):
        """Update download metadata without loading or replacing extracted records."""
        clean = sanitize_entry({k: v for k, v in item.items() if k != 'analysis'})
        previous = self.get(clean['url_hash'], include_records=False)
        if previous and previous.get('analysis'):
            clean['analysis'] = previous['analysis']
        with self.conn:
            self._put(clean)

    def replace(self, items):
        clean = [sanitize_entry(item) for item in items]
        with self.conn:
            self.conn.execute('DELETE FROM assets')
            for item in clean:
                self._put(item)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def entries(path):
    if not Path(path).exists() and not cache_db_path(path).exists():
        return {}
    with AssetCache(path) as cache:
        return {key: cache.get(key) for key in cache.keys()}


def write_entries(path, items):
    """Explicit snapshot export; hot-path updates use AssetCache.put_download."""
    clean = [sanitize_entry(x) for x in items.values()]
    if cache_db_path(path) != Path(path):
        private_write(path, ''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in clean))
    with AssetCache(path) as cache:
        cache.replace(clean)


def signature(record):
    return record['method'] + ' ' + record['url'] + ' ' + ','.join(sorted(record['body']['fields']))


def update_analysis(cache, key, content_hash, version, records):
    with AssetCache(cache) as store:
        item = store.get(key)
        if not item:
            raise ValueError('Download metadata not found')
        previous = item.get('analysis') or {}
        if item.get('content_hash') != content_hash:
            raise ValueError('Asset content differs from download metadata')
        before = {signature(r) for r in previous.get('records', [])}
        after = {signature(r) for r in records}
        kind = 'first_seen' if not previous else 'changed' if previous.get('content_hash') != content_hash else 'reanalyzed' if previous.get('analyzer_version') != version else 'unchanged'
        asset = {'content_hash': content_hash, 'analyzer_version': version, 'change_kind': kind, 'added_count': len(after-before), 'removed_count': len(before-after),
                 'delta_partial': previous.get('total_records', 0) > len(previous.get('records', [])), 'added_preview': [x[:512] for x in sorted(after-before)[:10]],
                 'removed_preview': [x[:512] for x in sorted(before-after)[:10]], 'reused': False}
        decorated = [attach_context(dict(record, asset=asset, context={}), {}) for record in records]
        item['analysis'] = {'content_hash': content_hash, 'analyzer_version': version, 'records': decorated, 'total_records': len(decorated)}
        store.put(item)
        return decorated


def reusable(item, version):
    analysis = item.get('analysis') or {}
    count = len(analysis['records']) if isinstance(analysis.get('records'), list) else analysis.get('record_count')
    return (analysis.get('content_hash') == item.get('content_hash') and analysis.get('analyzer_version') == version
            and count is not None and analysis.get('total_records', count) == count and analysis.get('complete', True))


def reuse_analysis(cache, mapping, version):
    output = []
    if not Path(mapping).exists() or (not Path(cache).exists() and not cache_db_path(cache).exists()):
        return output
    with AssetCache(cache) as store:
        for line in Path(mapping).read_text().splitlines():
            if '\t' not in line:
                continue
            filename, url = line.split('\t', 1)
            item = store.get(Path(filename).stem)
            if not item or item['url'] != safe_url(url) or not reusable(item, version):
                continue
            for record in item['analysis']['records']:
                r = native_record(record)
                r['asset'] = dict(r.get('asset') or {}, reused=True)
                output.append(r)
    return output
