"""Private, bounded reuse of complete model results; cached decisions are never fresh calls."""
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from .core import canonical, digest, invalid_json_constant
from .ai_review import _no_duplicates
from .codex_review import DEFAULT_MODEL, DEFAULT_REASONING_EFFORT

CACHE_VERSION = '8.9.0-4'
MAX_ENTRY = 512 * 1024


def runtime_fingerprint(model=None):
    from .codex_review import _configuration_snapshot
    snapshot = _configuration_snapshot(tempfile.gettempdir())
    if snapshot is None: return None
    environment, executable, files = snapshot
    stable_environment = []
    for key, value in environment:
        if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy'):
            try:
                proxy = urlsplit(value)
                if not proxy.scheme or not proxy.hostname: return None
                # Runtime broker credentials and loopback listener ports rotate per
                # process. They are transport handles, not model configuration.
                # Remote proxy routes and Codex auth/config remain separately bound.
                port = 'runtime-loopback' if proxy.hostname in ('localhost', '127.0.0.1', '::1') else proxy.port
                value = (proxy.scheme, proxy.hostname, port, proxy.path, proxy.query, proxy.fragment)
            except ValueError:
                return None
        stable_environment.append((key, value))
    # This includes secret-bearing local configuration/environment: persist its digest only.
    model = DEFAULT_MODEL if model is None else model
    return hashlib.sha256(repr((CACHE_VERSION, model, DEFAULT_REASONING_EFFORT,
                               stable_environment, executable, files)).encode()).hexdigest()


def verified_receipt(receipt, stage):
    return (isinstance(receipt, dict) and receipt.get('provider') == 'codex_chatgpt_login' and
        receipt.get('status') == 'completed' and receipt.get('model_execution_verified') is True and
        receipt.get('completion_events_verified') is True and receipt.get('tools_disabled') is True and receipt.get(stage) == 'verified')


class DecisionCache:
    def __init__(self, path, fingerprint, max_age=86400):
        self.fingerprint = fingerprint; self.max_age = max_age; self.invalid_entries = 0; self.write_errors = 0
        self.conn = None
        if path is None or fingerprint is None: return
        if not 1 <= max_age <= 30 * 86400: raise ValueError('Invalid AI cache age')
        path = Path(path)
        if path.is_symlink(): raise ValueError('AI cache must not be a symlink')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        os.close(fd)
        if not regular: raise ValueError('AI cache must be a regular file')
        if path.stat().st_size > 128 * 1024 * 1024: raise ValueError('AI cache size limit exceeded')
        path.chmod(0o600)
        try:
            self.conn = sqlite3.connect(path, timeout=10)
            self.conn.execute('PRAGMA trusted_schema=OFF')
            self.conn.execute('PRAGMA max_page_count=32768')
            self.conn.execute('CREATE TABLE IF NOT EXISTS model_cache (key TEXT PRIMARY KEY, created REAL NOT NULL, content TEXT NOT NULL, sha256 TEXT NOT NULL)')
            self.conn.commit()
        except sqlite3.Error:
            self.close(); raise ValueError('Invalid or unavailable AI cache') from None

    def key(self, namespace, value):
        return digest([CACHE_VERSION, namespace, self.fingerprint, value])

    def get(self, namespace, value, validator):
        if self.conn is None: return None
        key = self.key(namespace, value)
        try:
            row = self.conn.execute('SELECT created,content,sha256 FROM model_cache WHERE key=?', (key,)).fetchone()
        except sqlite3.Error:
            self.invalid_entries += 1
            return None
        if not row: return None
        created, text, sha = row
        if not isinstance(created, (int, float)) or not 0 <= time.time() - created <= self.max_age: return None
        try:
            if not isinstance(text, str) or len(text.encode()) > MAX_ENTRY or hashlib.sha256(text.encode()).hexdigest() != sha:
                raise ValueError('Invalid cache content')
            entry = json.loads(text, parse_constant=invalid_json_constant, object_pairs_hook=_no_duplicates)
            if entry['cache_key'] != key or entry['namespace'] != namespace: raise ValueError('Mismatched cache entry')
            if not isinstance(entry['receipt'], dict) or entry['receipt'].get('requested_reasoning_effort') != DEFAULT_REASONING_EFFORT:
                raise ValueError('Mismatched reasoning effort')
            result = validator(entry['packet'], entry['result'], entry['receipt'])
            return result, {'origin_packet_id': entry['packet']['packet_id'], 'origin_receipt': entry['receipt'],
                            'cached_at_epoch': created, 'cache_key': key}
        except (ValueError, TypeError, KeyError, RecursionError):
            self.invalid_entries += 1
            return None

    def put(self, namespace, value, packet, result, receipt):
        if self.conn is None: return
        if receipt.get('requested_reasoning_effort') != DEFAULT_REASONING_EFFORT: return
        if runtime_fingerprint(receipt.get('requested_model')) != self.fingerprint: return
        key = self.key(namespace, value)
        entry = {'cache_key': key, 'namespace': namespace, 'packet': packet, 'result': result, 'receipt': receipt}
        text = canonical(entry)
        if len(text.encode()) > MAX_ENTRY: return
        try:
            with self.conn:
                self.conn.execute('INSERT OR REPLACE INTO model_cache VALUES (?,?,?,?)', (key, time.time(), text, hashlib.sha256(text.encode()).hexdigest()))
                # Reusable analysis is expendable; cap growth without touching source evidence.
                self.conn.execute('DELETE FROM model_cache WHERE key IN (SELECT key FROM model_cache ORDER BY created DESC LIMIT -1 OFFSET 2000)')
        except sqlite3.Error:
            self.write_errors += 1  # A cache write failure must not erase a verified fresh result.

    def close(self):
        if self.conn is not None: self.conn.close(); self.conn = None
