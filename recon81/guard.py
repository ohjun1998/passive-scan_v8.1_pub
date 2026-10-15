"""Transactional shared request budget, pacing and circuit breaker. No retries."""
import json
import os
import sqlite3
import statistics
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException, IncompleteRead
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit
from .network_policy import PolicyDenied, NetworkPolicy


class GuardStopped(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def retry_after_seconds(value):
    try:
        if str(value).strip().isdigit():
            return max(0, int(value))
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, int((date - datetime.now(timezone.utc)).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return 0


class RunGuard:
    def __init__(self, path, max_requests=300, max_bytes=10*1024*1024, interval=1.0):
        if max_requests < 1 or max_bytes < 1 or interval < 0:
            raise ValueError('Invalid request budget')
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS guard (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO guard VALUES (1, ?)', (json.dumps({'requests':0,'bytes':0,'reserved_bytes':0,'last_request':0,'stopped':False,'reason':'','failures':0,'latencies':[],'slow':0,'retry_after':0,'costly_counts':{}}),))
        self.db.commit()
        self.max_requests, self.max_bytes, self.interval = max_requests, max_bytes, interval
        self.path.chmod(0o600)

    def state(self):
        with self.lock:
            return json.loads(self.db.execute('SELECT state FROM guard WHERE id=1').fetchone()[0])

    @contextmanager
    def transaction(self):
        # The lock protects this connection's threads; BEGIN IMMEDIATE protects
        # read/check/update against other processes using the same state file.
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                state = self.state()
                yield state
                self.db.execute('UPDATE guard SET state=? WHERE id=1', (json.dumps(state),))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    @staticmethod
    def _stopped(state):
        if state['stopped']:
            raise GuardStopped(state['reason'])

    def check(self):
        self._stopped(self.state())

    def stop(self, reason, retry_after=0):
        with self.transaction() as state:
            if not state['stopped']:
                state.update(stopped=True, reason=reason, retry_after=retry_after)
            reason = state['reason']
        raise GuardStopped(reason)

    def reserve(self, url=None):
        reason = ''
        with self.transaction() as state:
            self._stopped(state)
            if state['requests'] >= self.max_requests:
                reason = 'request_budget_exhausted'
            elif state['bytes'] >= self.max_bytes:
                reason = 'byte_budget_exhausted'
            if reason:
                state.update(stopped=True, reason=reason)
            else:
                if url and NetworkPolicy.is_costly(url):
                    host = urlsplit(url).hostname
                    counts = state.setdefault('costly_counts', {})
                    if counts.get(host, 0) >= 3:
                        raise GuardStopped('costly_request_budget_exhausted')
                    counts[host] = counts.get(host, 0) + 1
                scheduled = max(time.time(), state['last_request'] + self.interval)
                state['requests'] += 1
                state['last_request'] = scheduled
        if reason:
            raise GuardStopped(reason)
        while scheduled > time.time():
            time.sleep(max(0, min(0.05, scheduled-time.time())))
            self.check()
        if self.interval:
            self.check()

    def claim_bytes(self, size, deadline):
        """Reserve read capacity before a socket read, including concurrent reads."""
        while True:
            reason = ''
            with self.transaction() as state:
                self._stopped(state)
                held = state.setdefault('reserved_bytes', 0)
                available = self.max_bytes-state['bytes']-held
                claimed = min(size, max(0, available))
                if claimed:
                    state['reserved_bytes'] += claimed
                elif not held:
                    reason = 'byte_budget_exhausted'
                    state.update(stopped=True, reason=reason)
            if reason:
                raise GuardStopped(reason)
            if claimed:
                return claimed
            if time.monotonic() >= deadline:
                raise TimeoutError('response transfer deadline')
            time.sleep(0.01)

    def consume(self, size, reserved=0):
        if size < 0 or reserved < 0:
            raise ValueError('Invalid byte count')
        reason = ''
        with self.transaction() as state:
            state['reserved_bytes'] = max(0, state.get('reserved_bytes', 0)-reserved)
            state['bytes'] += size
            if state['bytes'] > self.max_bytes:
                reason = 'byte_budget_exhausted'
                state.update(stopped=True, reason=reason)
        if reason:
            raise GuardStopped(reason)

    def feedback(self, status=0, elapsed=0, failed=False, retry_after='', host=''):
        reason = ''
        with self.transaction() as state:
            self._stopped(state)
            metrics = state.setdefault('hosts', {}).setdefault(host, {'failures':0,'latencies':[],'slow':0}) if host else state
            bad = failed or status >= 500
            metrics['failures'] = metrics['failures'] + 1 if bad else 0
            if elapsed and not bad:
                baseline = statistics.median(metrics['latencies']) if len(metrics['latencies']) >= 5 else None
                slow = baseline is not None and elapsed > max(2.0, baseline*3)
                metrics['slow'] = metrics['slow'] + 1 if slow else 0
                if not slow:
                    metrics['latencies'] = (metrics['latencies'] + [elapsed])[-20:]
            if status in (429, 503):
                reason = 'overload_http_' + str(status)
                state['retry_after'] = retry_after_seconds(retry_after)
            elif metrics['failures'] >= 3:
                reason = 'consecutive_network_or_server_failures'
            elif metrics['slow'] >= 3:
                reason = 'sustained_latency_increase'
            if reason:
                state.update(stopped=True, reason=reason)
        if reason:
            raise GuardStopped(reason)

    def close(self):
        with self.lock:
            self.db.close()


class ProtectedHTTP:
    def __init__(self, policy, guard, timeout=8):
        self.policy, self.guard, self.timeout = policy, guard, timeout
        self.on_dispatch = None
        self.opener = build_opener(NoRedirect())

    def get(self, url, limit=1024*1024):
        return self.fetch(url, limit=limit)

    def fetch(self, url, method='GET', headers=None, data=None, approved_read_post=False, limit=1024*1024):
        if method not in ('GET', 'HEAD') and not (method == 'POST' and approved_read_post):
            raise PolicyDenied('non_read_method')
        self.policy.check(url, 'GET' if approved_read_post else method)
        for k,v in (headers or {}).items():
            if k.lower() in ('x-http-method-override','x-method-override','x-http-method','x-original-method') and str(v).upper() not in ('GET','HEAD'):
                raise PolicyDenied('non_read_method_override')
        self.guard.reserve(url)
        if self.on_dispatch is not None:
            self.on_dispatch(url)
        host = urlsplit(url).netloc
        started = time.monotonic()
        try:
            safe_headers = {k:v for k,v in (headers or {}).items() if k.lower() not in ('host', 'content-length', 'transfer-encoding', 'connection', 'accept-encoding', 'proxy-authorization')}
            safe_headers.update({'User-Agent':'PassiveScan protected-recon', 'Accept-Encoding':'identity'})
            try:
                response = self.opener.open(Request(url, headers=safe_headers, data=data, method=method), timeout=self.timeout)
            except HTTPError as error:
                response = error  # Error statuses still carry useful bounded evidence.
        except (URLError, OSError, HTTPException):
            self.guard.feedback(failed=True,host=host)
            return {'status':0,'headers':{},'body':b'','complete':False}
        with response:
            response_headers = dict(response.headers.items())
            status = response.status
            retry_after = next((v for k,v in response_headers.items() if k.lower()=='retry-after'), '')
            if status in (429, 503):
                self.guard.feedback(status,time.monotonic()-started,retry_after=retry_after,host=host)
            if method == 'HEAD' or status in (204, 304):
                self.guard.feedback(status,time.monotonic()-started,host=host)
                return {'status':status,'headers':response_headers,'body':b'','complete':True}
            lengths = [v for k,v in response.headers.items() if k.lower()=='content-length']
            transfer_encoding = next((v for k,v in response_headers.items() if k.lower()=='transfer-encoding'), '')
            if len(lengths)>1 or (lengths and transfer_encoding) or (transfer_encoding and transfer_encoding.lower()!='chunked'):
                self.guard.feedback(failed=True,host=host)
                return {'status':status,'headers':response_headers,'body':b'','complete':False}
            raw_length = next((v for k,v in response_headers.items() if k.lower()=='content-length'), '')
            length = int(raw_length) if raw_length.isdigit() else None
            if raw_length and length is None:
                self.guard.feedback(failed=True,host=host)
                return {'status':status,'headers':response_headers,'body':b'','complete':False}
            if length is not None and length > limit:
                self.guard.feedback(status,time.monotonic()-started,host=host)
                return {'status':status,'headers':response_headers,'body':b'','complete':False}
            chunks, read = [], 0
            try:
                while length is None or read < length:
                    if time.monotonic()-started >= self.timeout:
                        raise TimeoutError('response transfer deadline')
                    size = min(65536, limit+1-read, length-read if length is not None else limit+1)
                    if size <= 0:
                        break
                    claimed = self.guard.claim_bytes(size, started+self.timeout)
                    part = b''
                    try:
                        # read1 returns available bytes without waiting to fill a chunk.
                        sock = getattr(getattr(getattr(response,'fp',None),'raw',None),'_sock',None)
                        if sock is not None:
                            sock.settimeout(max(0.001,started+self.timeout-time.monotonic()))
                        part = response.read1(claimed)
                    except IncompleteRead as error:
                        part = error.partial
                        raise
                    finally:
                        self.guard.consume(len(part), reserved=claimed)
                    if not part:
                        break
                    chunks.append(part)
                    read += len(part)
                complete = read <= limit and (length is None or read == length)
            except (URLError, OSError, HTTPException):
                self.guard.feedback(failed=True,host=host)
                return {'status':status,'headers':response_headers,'body':b'','complete':False}
            self.guard.feedback(status,time.monotonic()-started,failed=not complete,host=host)
            return {'status':status,'headers':response_headers,'body':b''.join(chunks) if complete else b'', 'complete':complete}
