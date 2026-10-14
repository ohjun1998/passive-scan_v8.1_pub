"""Bounded saved-evidence review packets and strict result import. No HTTP client."""
import copy
import hashlib
import html
import json
import re
import shutil
import tempfile
from pathlib import Path
from .core import Scope, canonical, digest, invalid_json_constant, private_write, sanitize_value, sanitize_headers, safe_url

HEX = r'^[a-f0-9]{64}$'
ASSESSMENTS = {'suspicious': '의심 항목', 'likely_benign': '정상 동작 가능성', 'insufficient_evidence': '증거 부족'}
CONFIDENCE = {'low': '낮음', 'medium': '보통', 'high': '높음'}
INPUT_LIMIT = 128 * 1024 * 1024
RESULT_LIMIT = 1024 * 1024

def text_schema(limit):
    return {'type': 'string', 'maxLength': limit}

def object_schema(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}

STRINGS = {'type': 'array', 'maxItems': 30, 'items': text_schema(2000)}
SCHEMA = object_schema({
    'packet_id': {'type': 'string', 'pattern': HEX}, 'summary': text_schema(8000),
    'reviews': {'type': 'array', 'maxItems': 100, 'items': object_schema({
        'observation_ids': {'type': 'array', 'minItems': 1, 'maxItems': 20, 'uniqueItems': True, 'items': {'type': 'string', 'pattern': HEX}},
        'assessment': {'type': 'string', 'enum': list(ASSESSMENTS)},
        'confidence': {'type': 'string', 'enum': list(CONFIDENCE)},
        'reason': text_schema(4000), 'evidence_notes': STRINGS, 'next_checks': STRINGS,
        'report_draft': object_schema({'title': text_schema(500), 'impact': text_schema(4000), 'steps': STRINGS,
                                      'expected': text_schema(4000), 'actual': text_schema(4000), 'remediation': text_schema(4000)})})}})


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n'


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def load_json(path, limit=RESULT_LIMIT):
    return json.loads(read_bytes(path, limit), parse_constant=invalid_json_constant, object_pairs_hook=_no_duplicates)


def read_bytes(path, limit=INPUT_LIMIT):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular input file')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input size limit exceeded')
    return data


def _body(body):
    result = {k: copy.deepcopy(body[k]) for k in ('kind', 'text', 'fields', 'complete', 'reason', 'size_bytes') if k in body}
    text = result.get('text', '')
    if not isinstance(text, str):
        raise ValueError('Invalid body text')
    # Re-redact structured input too: reports may come from older/untrusted sources.
    if result.get('kind') == 'json':
        try:
            text = _json(sanitize_value(json.loads(text, parse_constant=invalid_json_constant)))
        except (ValueError, RecursionError):
            result.update(kind='omitted', complete=False, reason='malformed_structured_body')
            text = ''
    else:
        text = sanitize_value(text)
    encoded = text.encode('utf-8')
    if len(encoded) > 8192:
        text = encoded[:8192].decode('utf-8', errors='ignore')
        result.update(complete=False, reason='ai_body_byte_limit')
    result['text'] = text
    return result


def _evidence(record, scope):
    oid = record.get('observation_id', '')
    if not isinstance(oid, str) or not re.fullmatch(HEX, oid):
        raise ValueError('Invalid observation ID')
    result = {k: copy.deepcopy(record[k]) for k in ('observation_id', 'url', 'method', 'observed', 'timestamp', 'headers', 'triage') if k in record}
    result['url'] = safe_url(result['url'])
    result['headers'] = sanitize_headers(result.get('headers', []))
    origin = record.get('origin_url')
    if origin and scope.allows(origin):
        result['origin_url'] = safe_url(origin)
    result['context'] = {k: v for k, v in (record.get('context') or {}).items()
                         if k in ('actor', 'tenant', 'scenario', 'expected_access', 'operation', 'capture_id')}
    result['body'] = _body(record.get('body') or {})
    response = record.get('response')
    result['response'] = None if not response else {
        'status': response.get('status'), 'headers': sanitize_headers(response.get('headers', [])), 'body': _body(response.get('body') or {})}
    # Historical human verdicts, local source paths and raw provenance are not model instructions.
    return sanitize_value(result)


def _validate_schema(value, schema):
    kind = schema['type']
    if kind == 'object':
        if not isinstance(value, dict) or set(value) != set(schema['required']):
            raise ValueError('Result object fields do not match schema')
        for key, child in value.items():
            _validate_schema(child, schema['properties'][key])
    elif kind == 'array':
        if not isinstance(value, list) or not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 100):
            raise ValueError('Result array limit exceeded')
        if schema.get('uniqueItems') and len({canonical(x) for x in value}) != len(value):
            raise ValueError('Duplicate result IDs')
        for child in value:
            _validate_schema(child, schema['items'])
    elif kind == 'string':
        if not isinstance(value, str) or len(value) > schema.get('maxLength', 100000):
            raise ValueError('Invalid result text')
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
            raise ValueError('Invalid result ID')
        if 'enum' in schema and value not in schema['enum']:
            raise ValueError('Invalid assessment')


def verify_packet(packet):
    if not isinstance(packet, dict) or packet.get('schema_version') not in ('8.4','8.5'):
        raise ValueError('Unsupported packet version')
    content = dict(packet)
    claimed = content.pop('packet_id', None)
    if digest(content) != claimed:
        raise ValueError('Packet receipt mismatch')
    ids = [r['observation_id'] for r in packet['evidence']]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate packet evidence IDs')
    return packet


def validate_result(result, packet):
    verify_packet(packet)
    if packet.get('schema_version') == '8.5':
        from .review_evidence import validate_citations
        validate_citations(result, packet)
    else:
        _validate_schema(result, SCHEMA)
    if result['packet_id'] != packet['packet_id']:
        raise ValueError('Result is for a different packet')
    allowed = {r['observation_id'] for r in packet['evidence']}
    if any(not set(r['observation_ids']) <= allowed for r in result['reviews']):
        raise ValueError('Result references evidence outside this packet')
    return sanitize_value(result)


def build_packet(report, patterns, max_records=100, max_bytes=500000):
    if not 1 <= max_records <= 1000 or not 16384 <= max_bytes <= 2 * 1024 * 1024:
        raise ValueError('Invalid packet budget')
    report = Path(report).resolve()
    scope = Scope(patterns)
    requests = read_bytes(report / 'requests.jsonl')
    analysis_bytes = read_bytes(report / 'analysis.json')
    receipts = {name: hashlib.sha256(data).hexdigest() for name, data in
                [('requests.jsonl', requests), ('analysis.json', analysis_bytes)]}
    manifest_path = report / 'manifest.json'
    source_run_id = None
    if manifest_path.exists():
        manifest = load_json(manifest_path)
        for name, expected in receipts.items():
            if manifest.get('files', {}).get(name) != expected:
                raise ValueError('Source report receipt mismatch; regenerate the report')
        source_run_id = manifest.get('run_id')
    records = [json.loads(line, parse_constant=invalid_json_constant, object_pairs_hook=_no_duplicates)
               for line in requests.decode('utf-8').splitlines() if line.strip()]
    analysis = json.loads(analysis_bytes, parse_constant=invalid_json_constant, object_pairs_hook=_no_duplicates)
    scoped = [r for r in records if scope.allows(r.get('url', ''))]
    scoped.sort(key=lambda r: (not r.get('observed'), -(r.get('triage') or {}).get('score', 0), r['observation_id']))
    packet = {'schema_version': '8.4', 'source_run_id': source_run_id,
              'scope': {'patterns': scope.patterns}, 'source_receipts': receipts,
              'source_manifest_verified': source_run_id is not None,
              'evidence_trust': 'untrusted_captured_data', 'network_requests_sent': 0,
              'budget': {'max_records': max_records, 'max_bytes': max_bytes, 'body_max_bytes': 8192},
              'evidence': [], 'analysis': {'comparisons': []},
              'omissions': {'out_of_scope': len(records) - len(scoped), 'records': len(scoped),
                            'comparisons': len(analysis.get('comparisons', [])), 'partial_bodies': 0},
              'notice': '저장된 증거만 검토. 계정 라벨은 신원 검증이 아님. 마스킹은 최선의 노력이며 제공 전 사람이 확인.'}
    for record in scoped[:max_records]:
        evidence = _evidence(record, scope)
        packet['evidence'].append(evidence)
        packet['omissions']['records'] = len(scoped) - len(packet['evidence'])
        if len(_json(dict(packet, packet_id='0' * 64)).encode('utf-8')) > max_bytes:
            packet['evidence'].pop()
            packet['omissions']['records'] += 1
            break
    ids = {r['observation_id'] for r in packet['evidence']}
    for comparison in analysis.get('comparisons', []):
        if comparison.get('left_id') in ids and comparison.get('right_id') in ids:
            packet['analysis']['comparisons'].append(sanitize_value(comparison))
            packet['omissions']['comparisons'] -= 1
            if len(_json(dict(packet, packet_id='0' * 64)).encode('utf-8')) > max_bytes:
                packet['analysis']['comparisons'].pop()
                packet['omissions']['comparisons'] += 1
    packet['omissions']['partial_bodies'] = sum(not b.get('complete', False) for r in packet['evidence']
        for b in [r.get('body') or {}, (r.get('response') or {}).get('body') or {}])
    # Counters may gain digits, leaving a small final budget difference.
    while packet['evidence'] and len(_json(dict(packet, packet_id='0' * 64)).encode()) > max_bytes:
        packet['evidence'].pop()
        packet['omissions']['records'] += 1
        packet['analysis']['comparisons'] = []
        packet['omissions']['comparisons'] = len(analysis.get('comparisons', []))
    if not packet['evidence']:
        raise ValueError('No in-scope evidence fits the packet budget')
    packet['omissions']['partial_bodies'] = sum(not b.get('complete', False) for r in packet['evidence']
        for b in [r.get('body') or {}, (r.get('response') or {}).get('body') or {}])
    packet['packet_id'] = digest(packet)
    return packet


def _publish(output, files):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Use a new output directory; existing reports are never overwritten')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix='.ai-review-', dir=output.parent))
    try:
        for name, value in files.items():
            private_write(staging / name, value)
        receipts = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in files.items()}
        private_write(staging / 'manifest.json', _json({'schema_version': '8.4', 'files': receipts}))
        # mkdir reserves output exclusively; move individual files only after every write succeeded.
        output.mkdir(mode=0o700)
        for child in staging.iterdir():
            child.rename(output / child.name)
    finally:
        shutil.rmtree(staging)
    return output


def prepare_review(report, output, patterns, max_records=100, max_bytes=500000):
    from .codex_review import make_prompt
    packet = build_packet(report, patterns, max_records, max_bytes)
    _publish(output, {'packet.json': _json(packet), 'schema.json': _json(SCHEMA),
                     'prompt.txt': make_prompt(packet),
                     'execution.json': _json({'provider': 'manual', 'status': 'prepared', 'model_execution_verified': False,
                         'target_requests_sent': 0, 'human_confirmation_required': True})})
    return packet


def render_review(packet, result, output, execution):
    result = validate_result(result, packet)
    reviewed = {oid for r in result['reviews'] for oid in r['observation_ids']}
    selected = len(packet['evidence'])
    lines = ['# 저장 증거 AI 검토 보고서', '', 'AI 의견이며 취약점 확정·제출 승인은 사람이 수행합니다.', '',
             f'선택 증거 {selected}건 / 검토 의견에 연결된 증거 {len(reviewed)}건 / 미검토 {selected-len(reviewed)}건', '',
             result['summary'], '']
    for index, review in enumerate(result['reviews'], 1):
        draft = review['report_draft']
        lines.extend([f"## {index}. {draft['title']}", '',
            f"판단: {ASSESSMENTS[review['assessment']]} / 신뢰도: {CONFIDENCE[review['confidence']]}", '',
            review['reason'], '', '증거 ID: ' + ', '.join(review['observation_ids']), '', '근거:'])
        lines.extend('- ' + note for note in review['evidence_notes'])
        for label, key in [('영향', 'impact'), ('기대 동작', 'expected'), ('관찰 동작', 'actual'), ('개선안', 'remediation')]:
            lines.extend(['', label + ': ' + draft[key]])
        lines.extend(['', '관찰·재현 초안:'] + ['- ' + s for s in draft['steps']])
        lines.extend(['', '추가 확인 계획:'] + ['- ' + s for s in review['next_checks']] + [''])
    markdown = '\n'.join(lines) + '\n'
    # No model HTML/Markdown is interpreted in the HTML artifact.
    page = '<!doctype html><html lang="ko"><meta charset="utf-8"><title>AI 검토 보고서</title>' + \
           '<style>body{max-width:1000px;margin:40px auto;padding:20px;font:16px/1.65 sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>' + \
           '<h1>저장 증거 AI 검토 보고서</h1><pre>' + html.escape(markdown) + '</pre></html>'
    if packet.get('schema_version') == '8.5':
        from .review_evidence import validate_citations
        execution = dict(execution, citation_validation='verified', citation_count=len(validate_citations(result, packet)))
    else:
        execution = dict(execution, citation_validation='legacy_unverified')
    execution = dict(execution, packet_id=packet['packet_id'], selected_evidence=selected,
                     reviewed_evidence=len(reviewed), unreviewed_evidence=selected-len(reviewed),
                     target_requests_sent=0, human_confirmation_required=True)
    return _publish(output, {'packet.json': _json(packet), 'ai_review.json': _json(result),
                           'review.md': markdown, 'index.html': page, 'execution.json': _json(execution),
                           'citations.json': _json(validate_citations(result, packet) if packet.get('schema_version') == '8.5' else [])})


def import_review(packet_path, result_path, output):
    packet = verify_packet(load_json(packet_path, 2 * 1024 * 1024))
    result = load_json(result_path)
    return render_review(packet, result, output, {'provider': 'manual_import', 'status': 'imported',
                                               'model_execution_verified': False})
