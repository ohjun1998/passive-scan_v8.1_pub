"""Local request budget, pacing and circuit breaker. No automatic retry or resume."""
import json
import os
import sqlite3
import statistics
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from .network_policy import PolicyDenied, NetworkPolicy
from urllib.parse import urlsplit


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
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.execute('CREATE TABLE IF NOT EXISTS guard (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO guard VALUES (1, ?)', (json.dumps({'requests':0,'bytes':0,'last_request':0,'stopped':False,'reason':'','failures':0,'latencies':[],'slow':0,'retry_after':0,'costly_counts':{}}),))
        self.db.commit()
        self.max_requests, self.max_bytes, self.interval = max_requests, max_bytes, interval
        self.path.chmod(0o600)

    def state(self):
        return json.loads(self.db.execute('SELECT state FROM guard WHERE id=1').fetchone()[0])

    def _save(self, state):
        self.db.execute('UPDATE guard SET state=? WHERE id=1', (json.dumps(state),))
        self.db.commit()

    def check(self):
        if self.state()['stopped']:
            raise GuardStopped(self.state()['reason'])

    def stop(self, reason, retry_after=0):
        state = self.state()
        state.update(stopped=True, reason=reason, retry_after=retry_after)
        self._save(state)
        raise GuardStopped(reason)

    def reserve(self, url=None):
        self.check()
        state = self.state()
        if state['requests'] >= self.max_requests:
            raise GuardStopped('request_budget_exhausted')
        delay = max(0, state['last_request'] + self.interval - time.time())
        if delay:
            time.sleep(delay)
        if url and NetworkPolicy.is_costly(url):
            host = urlsplit(url).hostname
            counts = state.setdefault('costly_counts', {})
            if counts.get(host, 0) >= 3:
                raise GuardStopped('costly_request_budget_exhausted')
            counts[host] = counts.get(host, 0) + 1
        state['requests'] += 1
        state['last_request'] = time.time()
        self._save(state)

    def consume(self, size):
        state = self.state()
        if state['bytes'] + size > self.max_bytes:
            raise GuardStopped('byte_budget_exhausted')
        state['bytes'] += size
        self._save(state)

    def feedback(self, status=0, elapsed=0, failed=False, retry_after='', host=''):
        self.check()
        if status in (429, 503):
            self.stop('overload_http_' + str(status), retry_after_seconds(retry_after))
        state = self.state()
        metrics = state.setdefault('hosts', {}).setdefault(host, {'failures':0,'latencies':[],'slow':0}) if host else state
        bad = failed or status >= 500
        metrics['failures'] = metrics['failures'] + 1 if bad else 0
        if elapsed and not bad:
            baseline = statistics.median(metrics['latencies']) if len(metrics['latencies']) >= 5 else None
            slow = baseline is not None and elapsed > max(2.0, baseline*3)
            metrics['slow'] = metrics['slow'] + 1 if slow else 0
            if not slow:
                metrics['latencies'] = (metrics['latencies'] + [elapsed])[-20:]
        self._save(state)
        if metrics['failures'] >= 3:
            self.stop('consecutive_network_or_server_failures')
        if metrics['slow'] >= 3:
            self.stop('sustained_latency_increase')

    def close(self):
        self.db.close()


class ProtectedHTTP:
    def __init__(self, policy, guard, timeout=8):
        self.policy, self.guard, self.timeout = policy, guard, timeout
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
        host = urlsplit(url).netloc
        started = time.monotonic()
        try:
            safe_headers = {k:v for k,v in (headers or {}).items() if k.lower() not in ('host', 'content-length', 'connection', 'accept-encoding', 'proxy-authorization')}
            safe_headers.update({'User-Agent':'PassiveScan/8.2 protected-recon', 'Accept-Encoding':'identity'})
            response = self.opener.open(Request(url, headers=safe_headers, data=data, method=method), timeout=self.timeout)
        except HTTPError as error:
            try:
                self.guard.feedback(error.code, time.monotonic()-started, retry_after=error.headers.get('Retry-After',''),host=host)
                return {'status':error.code,'headers':dict(error.headers.items()),'body':b'','complete':300<=error.code<400}
            finally:
                error.close()
        except (URLError, OSError):
            self.guard.feedback(failed=True,host=host)
            return {'status':0,'headers':{},'body':b'','complete':False}
        with response:
            headers = dict(response.headers.items())
            if method == 'HEAD':
                self.guard.feedback(response.status,time.monotonic()-started,host=host)
                return {'status':response.status,'headers':headers,'body':b'','complete':True}
            length = headers.get('Content-Length','')
            if length.isdigit() and int(length) > limit:
                self.guard.feedback(response.status,time.monotonic()-started,host=host)
                return {'status':response.status,'headers':headers,'body':b'','complete':False}
            chunks = []
            read = 0
            try:
                while read <= limit:
                    if time.monotonic()-started >= self.timeout:
                        raise TimeoutError('response transfer deadline')
                    # read1 returns available data after one underlying read. read()
                    # can wait indefinitely for a full chunk on trickle responses.
                    part = response.read1(min(65536, limit + 1 - read))
                    if not part:
                        break
                    self.guard.consume(len(part))
                    chunks.append(part)
                    read += len(part)
            except (URLError, OSError):
                self.guard.feedback(failed=True,host=host)
                return {'status':response.status,'headers':headers,'body':b'','complete':False}
            self.guard.feedback(response.status,time.monotonic()-started,host=host)
            return {'status':response.status,'headers':headers,'body':b''.join(chunks) if read <= limit else b'', 'complete':read <= limit}
