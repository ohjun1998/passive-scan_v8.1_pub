"""Offline adapters. Inferred body fields never become observed payloads."""
import base64
import json
from pathlib import Path
from urllib.parse import urlencode, urljoin
from .core import (MASK, SECRET, MAX_BODY, normalize_record, packet, read_limited,
                   xml_root, sanitize_value, normalize_body, sanitize_headers,
                   header_pairs, get_header, digest, safe_url, now, redact_text, response_identity)


def har_body(request):
    post = request.get('postData')
    if post is None:
        return b'' if request.get('method', '').upper() in ('GET', 'HEAD') else None
    if 'text' in post:
        return post['text']
    if post.get('mimeType', '').split(';')[0] == 'application/x-www-form-urlencoded' and 'params' in post:
        return urlencode([(x['name'], x.get('value', '')) for x in post['params']])
    return None  # A schema or file metadata is not a captured raw payload.


def har_response(response):
    if not response:
        return None
    content = response.get('content') or {}
    body = content.get('text')
    if body is not None and content.get('encoding') == 'base64':
        body = base64.b64decode(body, validate=True)
    headers = list(header_pairs(response.get('headers', [])))
    if not get_header(headers, 'content-type') and content.get('mimeType'):
        headers.append(('Content-Type', content['mimeType']))
    return {'status': response.get('status', 0), 'headers': headers, 'body': body}


def har_entry(entry, include_text=False, source='har'):
    request = entry['request']
    headers = list(header_pairs(request.get('headers', [])))
    post = request.get('postData') or {}
    if not get_header(headers, 'content-type') and post.get('mimeType'):
        headers.append(('Content-Type', post['mimeType']))
    result = normalize_record(request['url'], request['method'], headers, har_body(request), har_response(entry.get('response')), source=source, timestamp=entry.get('startedDateTime'), include_text=include_text)
    if result['body']['kind'] == 'omitted' and 'params' in post:
        result['body']['fields'] = sorted({p['name'] for p in post['params']})
        # Recompute identities with the known fields, without manufacturing values.
        result = reidentify(result)
    return result


def reidentify(record):
    from urllib.parse import urlsplit, parse_qsl
    p = urlsplit(record['url'])
    ct = get_header(record['headers'], 'content-type').split(';')[0].lower()
    record['structure_id'] = digest([record['method'], p.scheme, p.netloc, p.path, sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)), ct, record['body']['fields'], record['observed']])
    identity_body = {k: v for k, v in record['body'].items() if k not in ('size_bytes', 'reason')}
    record['request_id'] = digest([record['url'], record['method'], record['headers'], identity_body, record['observed']])
    record['observation_id'] = digest([record['request_id'], response_identity(record['response']), record['source'], record.get('origin_url')])
    if record.get('context') or record.get('asset'):
        from .context import attach_context
        attach_context(record,record['context'])
    return record


def native_record(item, include_text=False):
    """Re-sanitize native JSONL; never trust imported redaction flags or hashes."""
    def body_input(body, ct):
        if not isinstance(body, dict):
            raise ValueError('Native body must be an object')
        kind = body.get('kind')
        if kind == 'empty':
            return normalize_body(b'', ct)
        if kind in ('json', 'form', 'xml', 'text'):
            if kind != 'text' and {'json': 'json', 'form': 'x-www-form-urlencoded', 'xml': 'xml'}[kind] not in ct.lower():
                raise ValueError('Native body kind and content type disagree')
            return normalize_body(body.get('text', ''), ct, include_text)
        if kind == 'multipart':
            parts = []
            for part in body.get('parts', []):
                name = str(part.get('name', ''))
                if 'filename' in part:
                    parts.append({'name': name, 'filename': redact_text(part['filename']), 'size_bytes': int(part.get('size_bytes', 0)), 'file_content': '[OMITTED]'})
                else:
                    parts.append({'name': name, 'value': MASK if SECRET.search(name) else sanitize_value(part.get('value', ''))})
            return {'kind': 'multipart', 'text': json.dumps(parts, ensure_ascii=False), 'parts': parts, 'fields': sorted({p['name'] for p in parts}), 'complete': False, 'reason': 'file_bytes_omitted_and_body_represented_as_parts'}
        if kind == 'omitted':
            return {'kind': 'omitted', 'text': '', 'fields': [str(x) for x in body.get('fields', [])], 'complete': False, 'reason': 'imported_omitted_body'}
        raise ValueError('Unsupported native body kind')
    observed = bool(item.get('observed', False))
    result = normalize_record(item['url'], item['method'], item.get('headers', []), source=str(item.get('source', 'native')), observed=observed, body_fields=(item.get('body') or {}).get('fields', []), timestamp=item.get('timestamp'), origin_url=item.get('origin_url'))
    if observed:
        result['body'] = body_input(item['body'], get_header(result['headers'], 'content-type'))
    if item.get('response'):
        resp = item['response']
        headers = sanitize_headers(resp.get('headers', []))
        result['response'] = {'status': int(resp.get('status', 0)), 'headers': headers, 'body': body_input(resp['body'], get_header(headers, 'content-type'))}
    from .context import clean_context
    result['context']=clean_context(item.get('context'))
    for key in ('schema','asset'):
        if key in item:
            from .discovery import clean_metadata
            result[key]=clean_metadata(item[key])
    return reidentify(result)


def js_record(item, base_url=None):
    raw = item['url']
    if not raw.startswith(('https://', 'http://')):
        if not base_url:
            raise ValueError('Relative JS URL requires --base-url or origin_url')
        raw = urljoin(base_url, raw)
    return normalize_record(raw, item.get('method') or 'UNKNOWN', item.get('headers'), source='jsluice', observed=False, body_fields=item.get('bodyParams', []), origin_url=base_url)


def burp_items(data, include_text=False):
    root = xml_root(data, allow_burp_dtd=True)
    if root.tag != 'items':
        raise ValueError('Expected Burp Save items XML; scanner issue XML is not supported')
    for item in root.findall('item'):
        def decode_node(name):
            node = item.find(name)
            if node is None:
                return None
            text = node.text or ''
            return base64.b64decode(''.join(text.split()), validate=True) if node.get('base64', '').lower() == 'true' else text.encode('utf-8')
        request = decode_node('request')
        if request is None:
            continue
        first, headers, body = packet(request)
        method = first.split(' ', 1)[0]
        resp = decode_node('response')
        response = None
        if resp:
            rf, rh, rb = packet(resp)
            status_parts = rf.split()
            if len(status_parts) < 2:
                raise ValueError('Malformed response status line')
            response = {'status': int(status_parts[1]), 'headers': rh, 'body': rb}
        yield normalize_record(item.findtext('url', ''), method, headers, body, response, 'burp', timestamp=item.findtext('time') or now(), include_text=include_text)


def load_records(path, fmt='auto', base_url=None, include_text=False):
    path = Path(path)
    if fmt == 'auto':
        fmt = {'.har': 'har', '.xml': 'burp', '.jsonl': 'jsonl', '.txt': 'urls','.json':'openapi','.yaml':'openapi','.yml':'openapi','.html':'html'}.get(path.suffix.lower())
        if not fmt:
            raise ValueError('Specify --format for this extension')
    data = read_limited(path)
    if fmt == 'openapi':
        from .discovery import openapi_records
        yield from openapi_records(data,base_url)
    elif fmt == 'html':
        from .discovery import form_records
        yield from form_records(data,base_url)
    elif fmt == 'har':
        for entry in json.loads(data)['log']['entries']:
            yield har_entry(entry, include_text)
    elif fmt == 'burp':
        yield from burp_items(data, include_text)
    elif fmt in ('jsonl', 'jsluice', 'urls'):
        for line in data.decode('utf-8-sig').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            if fmt == 'urls':
                yield normalize_record(line.strip(), 'UNKNOWN', source='url_list', observed=False)
                continue
            item = json.loads(line)
            if 'schema_version' in item:
                yield native_record(item, include_text)
            else:
                yield js_record(item, item.get('origin_url') or base_url)
    else:
        raise ValueError('Unsupported input format')
