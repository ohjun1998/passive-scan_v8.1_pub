"""Offline, evidence-linked leads. A lead is a test recommendation, never a verdict."""
import copy
import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit

from .core import MASK, Scope, canonical, digest, get_header, sanitize_headers, sanitize_value, safe_url, invalid_json_constant
from .review_evidence import authority_links, pointer, _leaves
from .analysis import comparison_selector

from .candidate_catalog import KINDS, CATALOG

RULE_VERSION = '8.8.0-1'
MAX_CANDIDATES = 5000
MAX_REFS = 8
DB_ERROR = re.compile(r'SQLSTATE\[[A-Z0-9]+\]|You have an error in your SQL syntax|'
    r'java\.sql\.(?:SQL\w*Exception)|ORA-\d{5}|Unclosed quotation mark|'
    r'unterminated quoted string|sqlite3\.(?:OperationalError|IntegrityError)|'
    r'Microsoft OLE DB Provider for SQL Server', re.I)
SOURCE = re.compile(r'\b(?:location\.(?:search|hash)|document\.(?:URL|referrer))\b')
SINK = re.compile(r'\.innerHTML\s*=|\bdocument\.write\s*\(|\.insertAdjacentHTML\s*\(|\beval\s*\(')
KEY_SHAPE = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|'
    r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|'
    r'\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|'
    r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bAIza[A-Za-z0-9_-]{20,}\b')
KEY_FIELD = re.compile(r'^(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|'
    r'private[_-]?key|secret[_-]?key|secret|token|password|passwd|pwd)$', re.I)
KEY_ASSIGN = re.compile(r'\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|'
    r'secret[_-]?key)\b[\s"\']*[:=][^\n;]{0,180}', re.I)
SENSITIVE = re.compile(r'^(?:password[_-]?hash|passwd[_-]?hash|ssn|social[_-]?security[_-]?number|'
    r'national[_-]?id|resident[_-]?number|bank[_-]?account|credit[_-]?card|salary|'
    r'email|phone|phone[_-]?number|date[_-]?of[_-]?birth|home[_-]?address)$', re.I)
IDENTIFIER = re.compile(r'^(?:id|uuid|user[_-]?id|owner[_-]?id|account[_-]?id|tenant[_-]?id|'
    r'order[_-]?id|file[_-]?id|document[_-]?id|project[_-]?id)$', re.I)
AUTH_PATH = re.compile(r'/(?:auth|oauth\d*|login|signin|session|token|refresh)(?:/|$)', re.I)


def scrub(value):
    """Re-redact old imports too; never persist an observed credential literal."""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in sanitize_value(value).items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return KEY_SHAPE.sub(MASK, sanitize_value(value))
    return value


def clean_record(record):
    result = copy.deepcopy(record)
    result['url'] = scrub(safe_url(record['url']))
    result['headers'] = scrub(sanitize_headers(record.get('headers', [])))
    for body in [result.get('body') or {}, (result.get('response') or {}).get('body') or {}]:
        text = body.get('text', '')
        if not isinstance(text, str):
            raise ValueError('Invalid candidate source body')
        if body.get('kind') == 'json' and body.get('complete'):
            body['text'] = canonical(scrub(json.loads(text, parse_constant=invalid_json_constant)))
        else:
            body['text'] = scrub(text)
    if result.get('response'):
        result['response']['headers'] = scrub(sanitize_headers(result['response'].get('headers', [])))
    result['context'] = scrub(result.get('context') or {})
    return result


def value_at(record, location, path):
    if location == 'url':
        if path: raise ValueError('URL evidence has no JSON pointer')
        return record['url']
    if location in ('context', 'authority'):
        return pointer(record.get(location) or {}, path)
    request = location.startswith('request.')
    parent = record if request else record.get('response') or {}
    if location.endswith('.headers'):
        return pointer(parent.get('headers', []), path)
    body = parent.get('body') or {}
    if location.endswith('.json'):
        if body.get('kind') != 'json' or not body.get('complete'):
            raise ValueError('JSON candidate evidence is incomplete')
        return pointer(json.loads(body['text'], parse_constant=invalid_json_constant), path)
    if path: raise ValueError('Text evidence has no JSON pointer')
    return body.get('text', '')


def reference(record, location, path='', start=0, end=None):
    value = value_at(record, location, path)
    text = value if isinstance(value, str) else canonical(value)
    end = min(len(text), start + 240) if end is None else min(end, len(text), start + 240)
    if start < 0 or end <= start: return None
    return {'observation_id': record['observation_id'], 'location': location, 'pointer': path,
            'start': start, 'end': end, 'excerpt': text[start:end]}


def validate_refs(candidate, records):
    allowed = set(candidate['subject_ids']) | set(candidate['support_ids'])
    if not candidate['subject_ids'] or set(candidate['subject_ids']) & set(candidate['support_ids']):
        raise ValueError('Candidate subjects and controls must be separate')
    for ref in candidate['evidence']:
        if ref['observation_id'] not in allowed or ref['observation_id'] not in records:
            raise ValueError('Candidate evidence outside subjects and controls')
        value = value_at(records[ref['observation_id']], ref['location'], ref['pointer'])
        text = value if isinstance(value, str) else canonical(value)
        if (type(ref['start']) is not int or type(ref['end']) is not int or
            not 0 <= ref['start'] < ref['end'] <= len(text) or
            text[ref['start']:ref['end']] != ref['excerpt']):
            raise ValueError('Candidate excerpt does not match saved evidence')
    if not any(r['observation_id'] in candidate['subject_ids'] for r in candidate['evidence']):
        raise ValueError('Candidate requires subject evidence')


def _leaves_of(record, request=False):
    body = (record if request else record.get('response') or {}).get('body') or {}
    if body.get('kind') == 'json' and body.get('complete'):
        return list(_leaves(json.loads(body['text'], parse_constant=invalid_json_constant)))
    return []


def _parameter_inputs(record, form=False):
    text = (record.get('body') or {}).get('text', '') if form else record['url']
    start = 0 if form else text.find('?') + 1
    if not form and start == 0: return []
    query = text if form else urlsplit(text).query
    result = []
    for segment in query.split('&'):
        for key, value in parse_qsl(segment, keep_blank_values=True):
            result.append((key, value, reference(record, 'request.body.text' if form else 'url', start=start)))
        start += len(segment) + 1
    return result


def _inputs(record):
    values = _parameter_inputs(record)
    body = record.get('body') or {}
    if body.get('kind') == 'form': values += _parameter_inputs(record, True)
    values += [(p, v, reference(record, 'request.body.json', p)) for p, v in _leaves_of(record, True) if isinstance(v, str)]
    result = []
    for key, value, ref in values:
        if not isinstance(value, str) or not 4 <= len(value) <= 160 or MASK in value: continue
        result.append((key, value, ref))
    return result


def recommend(records, patterns, authority=None):
    """Inspect every scoped saved body; keep rule processing distinct from AI coverage."""
    scope = Scope(patterns)
    scoped = [r for r in records if scope.allows(r['url'])]
    if any(not isinstance(r.get('observation_id'), str) or not re.fullmatch(r'[a-f0-9]{64}', r['observation_id']) for r in scoped):
        raise ValueError('Invalid candidate observation ID')
    links, _ = authority_links(scoped, authority, scope)
    clean = {r['observation_id']: clean_record(r) for r in scoped}
    for oid, r in clean.items(): r['authority'] = scrub(links.get(oid, {}))
    candidates = []; groups = defaultdict(list)
    for r in clean.values():
        selector = comparison_selector(r)
        if not selector['uncertain']: groups[selector['key']].append(r)

    def add(kind, record, rule, priority, strength, reason, refs, next_check, limitations=(), supports=(), lead_class='evidence_signal'):
        refs = [r for r in refs if r][:MAX_REFS]
        if not refs: return
        subject = record['observation_id']
        support_ids = sorted(set(supports) - {subject})
        candidate = {'candidate_id': digest([RULE_VERSION, kind, subject, rule, refs, support_ids]),
            'kind': kind, 'lead_class': lead_class, 'source_url': CATALOG[kind]['source_url'],
            'evidence_context': {'response_status': (record.get('response') or {}).get('status'),
                'response_content_type': get_header((record.get('response') or {}).get('headers', []), 'content-type'),
                'request_body_complete': bool((record.get('body') or {}).get('complete')),
                'response_body_complete': bool(((record.get('response') or {}).get('body') or {}).get('complete'))},
            'rule': rule, 'subject_ids': [subject], 'support_ids': support_ids,
            'method': record['method'], 'url': record['url'], 'priority': priority,
            'signal_strength': strength, 'reason': reason, 'evidence': refs,
            'context': record.get('context') or {}, 'authority': record.get('authority') or {},
            'limitations': list(limitations), 'next_check': next_check,
            'state': 'rule_candidate', 'ai': None, 'confirmed': False,
            'reproduction_verified': False, 'evidence_location_verified': True}
        validate_refs(candidate, clean)
        if len(candidates) >= MAX_CANDIDATES: raise ValueError('Candidate limit exceeded; narrow the source report')
        candidates.append(candidate)

    for original in scoped:
        r = clean[original['observation_id']]; response = r.get('response') or {}
        body = response.get('body') or {}; text = body.get('text', '')
        context = r.get('context') or {}; policy = (r.get('authority') or {}).get('policy') or {}
        expected = policy.get('expected_access', context.get('expected_access', 'unknown'))
        status = response.get('status', 0); leaves = _leaves_of(r)
        request_fields = [k for k, _ in parse_qsl(urlsplit(r['url']).query)] + list((r.get('body') or {}).get('fields', []))
        has_id = bool(re.search(r'/\d+(?:/|$)', urlsplit(r['url']).path) or
                      any(IDENTIFIER.match(re.split(r'[./\[\]]', f)[-1]) for f in request_fields))
        owner = next(((p, v) for p, v in leaves if re.search(r'/(?:ownerId|owner_id|userId|user_id|tenantId)$', p, re.I)), None)
        if r.get('observed') and expected == 'deny' and 200 <= status < 300 and text:
            selector = comparison_selector(r)
            controls = [x for x in groups.get(selector['key'], []) if x['observation_id'] != r['observation_id']
                        and x.get('context', {}).get('actor') != context.get('actor')
                        and (x.get('authority', {}).get('policy') or {}).get('expected_access', x.get('context', {}).get('expected_access')) == 'allow'][:2]
            refs = [reference(r, 'response.body.text'), reference(r, 'context', '/expected_access') if context.get('expected_access') else None]
            refs += [reference(x, 'response.body.text') for x in controls]
            add('idor' if has_id else 'authorization', r, 'declared_denial_with_saved_success',
                'high' if policy and controls else 'medium', 'medium',
                '차단을 기대한 저장 요청에 본문이 있는 2xx 응답이 있습니다. 실제 데이터 반환과 공통·로그인 응답을 구분해야 합니다.',
                refs, '대상 자원의 소유권·기대 권한을 확인하고 정상 대조군과 실제 반환 데이터를 비교하세요.',
                ['선언된 정책·계정 라벨은 실제 세션 신원이나 권한 위반의 독립 검증이 아닙니다.'],
                [x['observation_id'] for x in controls])
        elif r.get('observed') and expected == 'unknown' and has_id and owner and 200 <= status < 300:
            add('idor', r, 'identifier_and_returned_owner', 'low', 'low',
                '요청에 자원 식별자가 있고 응답에 소유자 관련 필드가 있어 객체 접근 정책을 검토할 수 있습니다.',
                [reference(r, 'url'), reference(r, 'response.body.json', owner[0])],
                '자원 소유자·현재 계정·허용 정책을 확보한 뒤 접근 권한을 판단하세요.',
                ['정상적인 본인 자원 조회일 수 있으며 현재는 권한 위반 근거가 없습니다.'])

        credential_params = [ref for key, _, ref in _parameter_inputs(r) if KEY_FIELD.match(key)]
        if credential_params:
            add('credential_exposure', r, 'credential_parameter_in_url', 'medium', 'low',
                'URL 쿼리에 자격정보 관련 파라미터가 있어 로그·방문 기록을 통한 노출을 검토할 수 있습니다.',
                credential_params, '파라미터의 용도·수명·공개 여부와 URL 기록 위치를 확인하세요.',
                ['파라미터 이름만으로 실제 비밀값이라고 판단하지 않습니다.'])
        if not r.get('observed') or not text: continue
        mime = get_header(response.get('headers', []), 'content-type').lower()
        html = 'html' in mime or bool(re.match(r'\s*<(?:!doctype|html)\b', text, re.I))
        script = 'javascript' in mime or urlsplit(r['url']).path.lower().endswith(('.js', '.mjs'))
        if html or script:
            for name, value, input_ref in _inputs(r):
                pos = text.find(value)
                if pos < 0: continue
                prefix = text[max(0, pos - 300):pos]
                in_script = script or prefix.lower().rfind('<script') > prefix.lower().rfind('</script')
                in_tag = prefix.rfind('<') > prefix.rfind('>')
                unsafe_chars = any(c in value for c in '<>"\'')
                if not (in_script or in_tag or unsafe_chars): continue
                add('xss', r, 'input_reflected_in_executable_context', 'medium', 'medium',
                    '저장된 입력값이 HTML 태그·속성·스크립트 문맥 또는 특수문자 형태로 반영됩니다.',
                    [input_ref, reference(r, 'response.body.text', start=max(0, pos - 70), end=pos + len(value) + 70)],
                    '반영 위치의 인코딩·문맥과 브라우저 실행 가능성을 확인하세요.',
                    ['입력 반영은 XSS 실행이나 인코딩 우회가 확인됐다는 뜻이 아닙니다.'])
                break
            source = SOURCE.search(text); sink = SINK.search(text)
            if source and sink:
                add('dom_based', r, 'client_source_and_sink_present', 'low', 'low',
                    '같은 저장 JS·HTML에서 외부 입력 소스와 위험 처리 지점이 함께 관찰됩니다.',
                    [reference(r, 'response.body.text', start=max(0, m.start() - 40), end=m.end() + 70) for m in (source, sink)],
                    '외부 입력이 해당 처리 지점에 실제로 도달하는지와 중간 정화·Trusted Types 처리를 추적하세요.',
                    ['동일 파일에 두 패턴이 있다는 사실만 확인했으며 데이터 흐름은 추적하지 않았습니다.'], lead_class='review_surface')

        error = DB_ERROR.search(text)
        if error:
            add('sqli', r, 'database_error_in_response', 'medium', 'low',
                '저장 응답에서 구체적인 DB 오류 패턴이 관찰됩니다. 입력과의 관련성을 조사할 후보입니다.',
                [reference(r, 'response.body.text', start=max(0, error.start() - 40), end=error.end() + 120)],
                '관련 입력을 특정하고 정상·조건 변경·오류 응답의 일관된 차이를 별도 검증하세요.',
                ['DB 오류는 SQLi의 증명이 아니며 일반 오류·예제 문서일 수 있습니다. Blind SQLi는 정상 패킷만으로 배제할 수 없습니다.'])

        sensitive = [(p, v) for p, v in leaves if SENSITIVE.match(p.rsplit('/', 1)[-1]) and v not in ('', None, False)]
        if sensitive:
            add('sensitive_data', r, 'sensitive_response_fields', 'high' if expected == 'deny' else 'medium', 'low',
                '응답에 민감할 수 있는 필드가 있습니다. 제공 대상과 필드별 공개 정책을 확인해야 합니다.',
                [reference(r, 'response.body.json', p) for p, _ in sensitive],
                '본인에게 필요한 정보인지, 다른 사용자·비공개 관리 정보가 포함되는지 확인하세요.',
                ['필드 이름만으로 비공개 정보라고 확정하지 않습니다. 마스킹된 값의 원문·유효성은 알 수 없습니다.'])

        auth_response = bool(AUTH_PATH.search(urlsplit(r['url']).path))
        secret_fields = [(p, v) for p, v in leaves if KEY_FIELD.match(p.rsplit('/', 1)[-1]) and v not in ('', None, False)
                         and not (auth_response and re.fullmatch(r'(?:access[_-]?token|refresh[_-]?token|token)', p.rsplit('/', 1)[-1], re.I))]
        original_text = ((original.get('response') or {}).get('body') or {}).get('text', '')
        shape = KEY_SHAPE.search(original_text)
        assignment = KEY_ASSIGN.search(text) if html or script else None
        if secret_fields or shape or assignment:
            refs = [reference(r, 'response.body.json', p) for p, _ in secret_fields]
            if not refs:
                match = assignment or re.search(re.escape(MASK), text)
                if match: refs = [reference(r, 'response.body.text', start=max(0, match.start() - 70), end=match.end() + 90)]
            add('credential_exposure', r, 'credential_in_response', 'medium', 'low',
                '응답·클라이언트 자료에 비밀값 필드 또는 자격정보 형식의 단서가 있습니다.', refs,
                '공개용 클라이언트 식별자·예제인지, 비공개 서버 자격정보인지와 노출 범위를 확인하세요. 원문 값으로 외부 인증을 시도하지 마세요.',
                ['정상 토큰 발급 응답·공개 API 식별자일 수 있습니다. 마스킹은 값의 유효성이나 원래 존재 여부를 보증하지 않습니다.'])

    from .candidate_extended import extend_record
    for record in clean.values(): extend_record(record, add)

    order = {'high': 0, 'medium': 1, 'low': 2}
    candidates.sort(key=lambda c: (c['lead_class'] == 'review_surface', order[c['priority']], c['kind'], c['candidate_id']))
    return candidates, clean, len(records) - len(scoped)
