"""Normalization, conservative redaction and local evidence storage. No network calls."""
import base64
import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = '[REDACTED]'
MAX_BODY = 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
SECRET = re.compile(r'password|passwd|pwd|secret|token|authorization|cookie|api.?key|csrf|xsrf|session|credential|private.?key|client.?secret|otp|verification.?code|^auth$|^x-auth$|^accesskey$', re.I)
JWT = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')
KEY_VALUE = re.compile(r'(?i)((?:password|passwd|secret|token|api[_-]?key|csrf|session)[\w-]*\s*[:=]\s*)[^\s,;]+')


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def redact_text(text):
    text = JWT.sub(MASK, str(text))
    text = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer ' + MASK, text)
    text = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b', MASK, text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', MASK, text, flags=re.S)
    return KEY_VALUE.sub(lambda m: m[1] + MASK, text)


def sanitize_value(value):
    if isinstance(value, dict):
        return {str(k): MASK if SECRET.search(str(k)) else sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    return redact_text(value) if isinstance(value, str) else value


def safe_url(url):
    parsed = urlsplit(str(url))
    host = parsed.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    port = parsed.port
    if port and not ((parsed.scheme == 'https' and port == 443) or (parsed.scheme == 'http' and port == 80)):
        host += ':' + str(port)
    query = urlencode([(k, MASK if SECRET.search(k) else redact_text(v)) for k, v in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme.lower(), host.lower(), redact_text(parsed.path or '/'), query, ''))


class Scope:
    """Exact hosts and *.suffix patterns. No substring matches."""
    def __init__(self, patterns):
        self.patterns = []
        for value in patterns:
            value = value.strip().lower()
            if not value or value.startswith('#'):
                continue
            if '://' in value:
                value = urlsplit(value).hostname or ''
            if '/' in value or ':' in value or not re.fullmatch(r'(?:\*\.)?[a-z0-9.-]+', value):
                raise ValueError('Invalid scope host pattern')
            self.patterns.append(value.rstrip('.'))
        if not self.patterns:
            raise ValueError('At least one scope host is required')

    def allows(self, url):
        try:
            p = urlsplit(url)
            _ = p.port
            if p.scheme not in ('http', 'https') or p.username or p.password:
                return False
            host = (p.hostname or '').lower().rstrip('.')
            return any(host == x or (x.startswith('*.') and (host == x[2:] or host.endswith('.' + x[2:]))) for x in self.patterns)
        except ValueError:
            return False


def header_pairs(headers):
    if isinstance(headers, dict):
        return [(str(k), str(v)) for k, v in headers.items()]
    return [(str(h['name']), str(h.get('value', ''))) if isinstance(h, dict) else (str(h[0]), str(h[1])) for h in (headers or [])]


def get_header(headers, name):
    return next((v for k, v in header_pairs(headers) if k.lower() == name.lower()), '')


def sanitize_headers(headers):
    result = []
    for name, value in header_pairs(headers):
        if name.lower() in ('content-length', 'transfer-encoding', 'content-encoding'):
            continue  # Saved bodies have been decoded / redacted.
        if SECRET.search(name):
            value = MASK
        elif name.lower() in ('location', 'referer', 'referrer'):
            try:
                value = safe_url(value)
            except ValueError:
                value = MASK
        else:
            value = redact_text(value)
        result.append({'name': name, 'value': value})
    return result


def xml_root(data, allow_burp_dtd=False):
    if isinstance(data, bytes):
        if data.startswith((b'\x00\x00\xfe\xff', b'\xff\xfe\x00\x00')):
            text = data.decode('utf-32')
        elif data.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = data.decode('utf-16')
        else:
            text = data.decode('utf-8-sig')
    else:
        text = data
    if re.search(r'<!ENTITY\b|\bSYSTEM\s+[\'\"]|\bPUBLIC\s+[\'\"]', text, re.I):
        raise ValueError('XML entities and external DTDs are not allowed')
    if re.search(r'<!DOCTYPE\b', text, re.I):
        if not allow_burp_dtd:
            raise ValueError('Body DTDs are not allowed')
        text = re.sub(r'<!DOCTYPE[^>\[]*(?:\[[\s\S]*?\]\s*)?>', '', text, flags=re.I)
    return ET.fromstring(text)


def field_paths(value, prefix='$'):
    result = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = prefix + '.' + str(key)
            result.add(path)
            result.update(field_paths(child, path))
    elif isinstance(value, list):
        result.add(prefix + '[]')
        for child in value:
            result.update(field_paths(child, prefix + '[]'))
    return sorted(result)


def omitted(reason, size=0):
    return {'kind': 'omitted', 'text': '', 'fields': [], 'complete': False, 'reason': reason, 'size_bytes': size}


def normalize_body(data, content_type='', include_text=False):
    if data is None:
        return omitted('body_not_captured')
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data:
        return {'kind': 'empty', 'text': '', 'fields': [], 'complete': True, 'size_bytes': 0}
    if len(data) > MAX_BODY:
        return omitted('body_size_limit', len(data))
    mime = content_type.split(';', 1)[0].strip().lower()
    if mime.startswith('multipart/'):
        try:
            msg = BytesParser(policy=policy.default).parsebytes(b'Content-Type: ' + content_type.encode('ascii') + b'\r\nMIME-Version: 1.0\r\n\r\n' + data)
            if not msg.is_multipart():
                return omitted('invalid_multipart', len(data))
            parts = []
            for part in msg.iter_parts():
                name = part.get_param('name', header='content-disposition') or ''
                filename = part.get_filename()
                payload = part.get_payload(decode=True) or b''
                if filename is not None:
                    parts.append({'name': name, 'filename': redact_text(filename), 'size_bytes': len(payload), 'file_content': '[OMITTED]'})
                else:
                    value = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                    parts.append({'name': name, 'value': MASK if SECRET.search(name) else redact_text(value)})
            return {'kind': 'multipart', 'text': json.dumps(parts, ensure_ascii=False), 'parts': parts, 'fields': sorted({p['name'] for p in parts}), 'complete': False, 'reason': 'file_bytes_omitted_and_body_represented_as_parts', 'size_bytes': len(data)}
        except (ValueError, UnicodeError, LookupError):
            return omitted('invalid_multipart', len(data))
    try:
        charset = re.search(r'charset\s*=\s*[\"\']?([^;\"\'\s]+)', content_type, re.I)
        text = data.decode(charset[1] if charset else 'utf-8-sig')
    except (UnicodeError, LookupError):
        return omitted('binary_or_unsupported_encoding', len(data))
    try:
        if mime == 'application/json' or mime.endswith('+json'):
            clean = sanitize_value(json.loads(text))
            return {'kind': 'json', 'text': json.dumps(clean, ensure_ascii=False, indent=2), 'fields': field_paths(clean), 'complete': True, 'size_bytes': len(data)}
        if mime == 'application/x-www-form-urlencoded':
            pairs = [(k, MASK if SECRET.search(k) else redact_text(v)) for k, v in parse_qsl(text, keep_blank_values=True)]
            return {'kind': 'form', 'text': urlencode(pairs), 'fields': sorted({k for k, _ in pairs}), 'complete': True, 'size_bytes': len(data)}
        if mime in ('application/xml', 'text/xml') or mime.endswith('+xml'):
            root = xml_root(text)
            paths = set()
            def clean_xml(element, path):
                tag = element.tag.split('}')[-1]
                path += '/' + tag
                paths.add(path)
                if SECRET.search(tag):
                    element.clear()
                    element.text = MASK
                    return
                element.text = redact_text(element.text) if element.text else element.text
                element.tail = redact_text(element.tail) if element.tail else element.tail
                for key, value in list(element.attrib.items()):
                    element.set(key, MASK if SECRET.search(key) else redact_text(value))
                for child in element:
                    clean_xml(child, path)
            clean_xml(root, '')
            return {'kind': 'xml', 'text': ET.tostring(root, encoding='unicode'), 'fields': sorted(paths), 'complete': True, 'size_bytes': len(data)}
    except (ValueError, RecursionError, ET.ParseError):
        return omitted('malformed_structured_body', len(data))
    if include_text:
        return {'kind': 'text', 'text': redact_text(text), 'fields': [], 'complete': True, 'size_bytes': len(data), 'reason': 'free_text_redaction_is_best_effort'}
    return omitted('unstructured_body_requires_include_text', len(data))


def decode_content(data, headers):
    encoding = get_header(headers, 'content-encoding').lower()
    if encoding == 'gzip':
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                return stream.read(MAX_BODY + 1)
        except (OSError, EOFError):
            return None
    if encoding and encoding != 'identity':
        return None
    return data


def packet(data):
    if not data:
        return '', [], b''
    sep = b'\r\n\r\n' if b'\r\n\r\n' in data else b'\n\n'
    head, _, body = data.partition(sep)
    lines = head.decode('iso-8859-1').splitlines()
    headers = []
    for line in lines[1:]:
        if line.startswith((' ', '\t')) and headers:
            headers[-1][1] += ' ' + line.strip()
        elif ':' in line:
            k, v = line.split(':', 1)
            headers.append([k.strip(), v.strip()])
    if get_header(headers, 'transfer-encoding').lower() == 'chunked':
        chunks = bytearray()
        complete = False
        try:
            while body:
                line, body = body.split(b'\r\n', 1)
                n = int(line.split(b';')[0], 16)
                if n == 0:
                    complete = True
                    break
                if n > len(body) or len(chunks) + n > MAX_BODY:
                    return lines[0], headers, None
                chunks += body[:n]
                body = body[n:]
                if not body.startswith(b'\r\n'):
                    raise ValueError('Invalid chunk framing')
                body = body[2:]
            body = bytes(chunks) if complete else None
        except ValueError:
            body = None
    return lines[0] if lines else '', headers, decode_content(body, headers) if body is not None else None



def response_identity(response):
    if response is None:
        return None
    result = dict(response)
    result['body'] = {k: v for k, v in response['body'].items() if k not in ('size_bytes', 'reason')}
    return result


def normalize_record(url, method, headers=None, body=None, response=None, source='import', observed=True, body_fields=None, include_text=False, timestamp=None, origin_url=None):
    method = str(method or 'UNKNOWN').upper()
    if not re.fullmatch(r'[A-Z!#$%&\'*+.^_`|~-]{1,32}', method):
        raise ValueError('Invalid HTTP method')
    request_type = get_header(headers, 'content-type')
    request_body = normalize_body(body, request_type, include_text)
    if not observed:
        request_body = omitted('static_structure_only')
        request_body['fields'] = sorted(set(str(x) for x in (body_fields or [])))
    resp = None
    if response is not None:
        rh = response.get('headers', [])
        resp = {'status': int(response.get('status') or 0), 'headers': sanitize_headers(rh), 'body': normalize_body(response.get('body'), get_header(rh, 'content-type'), include_text)}
    record = {'schema_version': '8.1', 'url': safe_url(url), 'method': method, 'headers': sanitize_headers(headers), 'body': request_body, 'response': resp, 'source': redact_text(str(source)), 'observed': bool(observed), 'timestamp': timestamp or now(), 'origin_url': safe_url(origin_url) if origin_url else None}
    p = urlsplit(record['url'])
    # Preserve full path, method, query key multiplicity and body structure.
    record['structure_id'] = digest([method, p.scheme, p.netloc, p.path, sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)), request_type.split(';')[0].lower(), request_body['fields'], observed])
    identity_body = {k: v for k, v in request_body.items() if k not in ('size_bytes', 'reason')}
    record['request_id'] = digest([record['url'], method, record['headers'], identity_body, observed])
    record['observation_id'] = digest([record['request_id'], response_identity(resp), record['source'], record['origin_url']])
    return record


def read_limited(path):
    with open(path, 'rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError('Input file exceeds 128 MiB limit')
    return data


def private_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(data)
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Inventory:
    def __init__(self, path='reports/request_inventory.sqlite3'):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute('CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, structure_id TEXT NOT NULL, record TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER NOT NULL)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS structures ON observations(structure_id)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS requests ON observations(request_id)')

    def add(self, record):
        t = now()
        self.conn.execute('INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, 1) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, seen_count=seen_count+1', (record['observation_id'], record['request_id'], record['structure_id'], canonical(record), t, t))

    def records(self):
        for record, count, first, last in self.conn.execute('SELECT record, seen_count, first_seen, last_seen FROM observations ORDER BY structure_id, id'):
            data = json.loads(record)
            data.update(seen_count=count, first_seen=first, last_seen=last)
            yield data

    def close(self):
        self.conn.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if args[0]:
            self.conn.rollback()
            self.conn.close()
        else:
            self.close()
