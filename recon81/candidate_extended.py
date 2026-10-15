"""Offline signals and clearly separated inspection surfaces; never sends requests."""
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .core import MASK, canonical, get_header

ERRORS = {
    'command_injection': re.compile(r'(?:/bin/(?:ba)?sh|\bcmd\.exe):[^\n]{0,100}(?:not found|syntax error|not recognized)|is not recognized as an internal or external command', re.I),
    'ssti': re.compile(r'jinja2\.exceptions\.(?:TemplateSyntaxError|UndefinedError)|Twig\\Error\\(?:SyntaxError|RuntimeError)|freemarker\.core\.(?:ParseException|InvalidReferenceException)|org\.thymeleaf\.exceptions\.', re.I),
    'nosql_injection': re.compile(r'\b(?:MongoServerError|MongoError|BSONError)\b|unknown (?:top level )?operator:\s*\$\w+', re.I),
    'deserialization': re.compile(r'java\.io\.(?:InvalidClassException|StreamCorruptedException)|ObjectInputStream\.readObject|pickle\.UnpicklingError|unserialize\(\): Error at offset', re.I),
    'information_disclosure': re.compile(r'Traceback \(most recent call last\)|PHP (?:Fatal|Parse) error:|Stack trace:\s*#0|\bat [\w.$]+\([^\n]{1,100}\.java:\d+\)|Server Error in [^\n]{1,80} Application', re.I),
}
XML_ERROR = re.compile(r'SAXParseException|XMLSyntaxError|libxml[^\n]{0,70}error|failed to load external entity', re.I)
XML_BLOCK = re.compile(r'(?:DOCTYPE|DTD|external entit\w*)[^\n]{0,60}(?:disallow|disable|prohibit|forbid)', re.I)
URL_FIELDS = re.compile(r'^(?:url|uri|endpoint|callback|webhook|feed|proxy|destination|image_url|target_url)$', re.I)
FILE_FIELDS = re.compile(r'^(?:file|filename|path|filepath|document|template)$', re.I)
MONEY_FIELDS = re.compile(r'^(?:quantity|qty|price|amount|total|discount)$', re.I)
WRITE_PATH = re.compile(r'/(?:redeem|checkout|transfer|coupon|purchase|withdraw|payment)(?:/|$)', re.I)
AUTH_PATH = re.compile(r'/(?:login|signin|register|password-reset|reset-password)(?:/|$)', re.I)
CSRF_FIELD = re.compile(r'csrf|xsrf|requestverificationtoken|authenticity_token', re.I)


def extend_record(r, add):
    # Import lazily because the base engine supplies the shared source/ref validator.
    from .candidate_rules import reference, _parameter_inputs, _leaves_of
    if not r.get('observed'): return
    response = r.get('response') or {}; rb = response.get('body') or {}; request = r.get('body') or {}
    text = rb.get('text', ''); request_text = request.get('text', '')
    status = response.get('status', 0); ok = 200 <= status < 300
    path = urlsplit(r['url']).path; mime = get_header(response.get('headers', []), 'content-type').lower()
    request_mime = get_header(r.get('headers', []), 'content-type').lower()
    html = 'html' in mime or bool(re.match(r'\s*<(?:!doctype|html)\b', text, re.I))
    script = 'javascript' in mime or path.lower().endswith(('.js', '.mjs'))
    leaves = _leaves_of(r); request_leaves = _leaves_of(r, True)
    values = _parameter_inputs(r)
    if request.get('kind') == 'form': values += _parameter_inputs(r, True)
    values += [(p.rsplit('/', 1)[-1], v, reference(r, 'request.body.json', p)) for p, v in request_leaves if isinstance(v, str)]
    fields = list(request.get('fields', [])) + [p for p, _ in request_leaves] + [k for k, _ in parse_qsl(urlsplit(r['url']).query, keep_blank_values=True)]
    def header(name, response_side=False):
        return get_header((response if response_side else r).get('headers', []), name)
    def href(name, response_side=False):
        parent = response if response_side else r
        return next((reference(r, 'response.headers' if response_side else 'request.headers', '/' + str(i) + '/value')
            for i, h in enumerate(parent.get('headers', [])) if h['name'].lower() == name.lower()), None)
    def bodyref(match=None, request_side=False):
        return reference(r, 'request.body.text' if request_side else 'response.body.text',
                         start=max(0, match.start() - 45) if match else 0)
    def emit(kind, rule, reason, refs, check, limitation, surface=False):
        add(kind, r, rule, 'low' if surface else 'medium', 'low', reason, refs, check,
            [limitation, '저장 자료의 단서·점검 대상이며 취약점 확정이나 재현 결과가 아닙니다.'],
            lead_class='review_surface' if surface else 'evidence_signal')

    for kind, pattern in ERRORS.items():
        match = pattern.search(text)
        if match:
            emit(kind, 'specific_runtime_error', '관련 처리기의 구체적인 오류 패턴이 저장 응답에 있습니다.', [bodyref(match)],
                 '입력과 오류의 연관 및 실제 실행 경로·공개 정책을 확인하세요.',
                 '일반 처리 실패나 문서 예제일 수 있으며 오류만으로 주입·코드 실행을 입증하지 않습니다.')

    for name, value, ref in values:
        if not isinstance(value, str) or MASK in value or len(value) > 2048: continue
        decoded = unquote(unquote(value))
        if FILE_FIELDS.fullmatch(name):
            traversal = bool(re.search(r'(?:^|[\\/])\.\.[\\/]', decoded))
            file_content = bool(re.search(r'(?m)^root:[^\n]*:[0-9]+:[0-9]+:|\[(?:boot loader|operating systems)\]', text))
            if status < 400:
                emit('path_traversal', 'file_selector_with_traversal' if traversal else 'file_selector_surface',
                     '파일 선택 입력에서 상위 경로 표기와 파일 형식 응답이 함께 관찰됩니다.' if traversal and file_content else '파일·경로 선택 입력이 있어 파일 경계 점검 대상입니다.',
                     [ref, bodyref() if traversal and file_content else None], '요청 경로가 허용 디렉터리를 벗어나는지와 실제 반환 파일을 확인하세요.',
                     '파일 선택 기능과 경로 표기만으로 디렉터리 이탈을 확정하지 않습니다.', surface=not (traversal and file_content))
                break

    for name, value, ref in values:
        if not URL_FIELDS.fullmatch(name) or not isinstance(value, str) or MASK in value or len(value) > 2048: continue
        try: target = urlsplit(value)
        except ValueError: continue
        if target.scheme not in ('http', 'https') or not target.hostname: continue
        host = target.hostname
        network_error = re.search(r'(?:ECONNREFUSED|ENOTFOUND|connect\(\) failed|connection refused)[^\n]{0,140}', text, re.I)
        related = bool(network_error and host in network_error.group(0))
        emit('ssrf', 'url_input_and_network_error' if related else 'server_url_input_surface',
             'URL 입력과 같은 호스트를 포함한 접속 오류가 저장돼 있습니다.' if related else '서버가 사용할 수 있는 URL 입력이 있어 목적지 정책 점검 대상입니다.',
             [ref, bodyref(network_error) if related else None], '해당 기능이 서버에서 접속하는지와 목적지 허용 정책을 확인하세요.',
             'URL·오류의 동시 관찰은 서버 접속이나 내부망 접근의 증명이 아닙니다. DNS·외부 접속은 수행하지 않았습니다.', surface=not related)
        break

    xml_request = request.get('kind') == 'xml' or 'xml' in request_mime
    xml_error = XML_ERROR.search(text)
    if xml_request and not XML_BLOCK.search(text):
        emit('xxe', 'xml_parser_error' if xml_error else 'xml_processing_surface',
             'XML 입력에 관련 파서 오류가 응답에 있습니다.' if xml_error else 'XML 입력 처리 기능이 있어 파서 설정 점검 대상입니다.',
             [href('content-type'), bodyref(request_side=True), bodyref(xml_error) if xml_error else None],
             '외부 엔티티·DTD·XInclude 허용 설정과 실제 파싱 경로를 확인하세요.',
             '엔티티를 확장하거나 DTD를 읽지 않습니다. 가져오기 단계에서 위험 XML이 생략됐을 수 있습니다.', surface=not bool(xml_error))

    if ok and request_leaves:
        negative = [(p, v) for p, v in request_leaves if MONEY_FIELDS.fullmatch(p.rsplit('/', 1)[-1]) and type(v) in (int, float) and v < 0]
        if negative:
            emit('business_logic', 'negative_business_value_with_success', '음수 금액·수량 입력에 성공 상태가 저장돼 있습니다.',
                 [reference(r, 'request.body.json', p) for p, _ in negative] + [bodyref()],
                 '환불·할인 등 허용 업무 규칙과 실제 반영된 최종 금액·상태를 확인하세요.',
                 '음수 값은 합법적인 환불·할인일 수 있고 2xx도 업무 성공을 보증하지 않습니다.')
    if r['method'] in ('POST', 'PUT', 'PATCH', 'DELETE') and WRITE_PATH.search(path):
        refs = [reference(r, 'url'), bodyref(request_side=True)]
        for kind in ('business_logic', 'race_conditions'):
            if kind == 'business_logic' and ok and any(MONEY_FIELDS.fullmatch(p.rsplit('/', 1)[-1]) and type(v) in (int, float) and v < 0 for p, v in request_leaves): continue
            emit(kind, 'stateful_business_operation_surface', '상태·금액에 영향을 줄 수 있는 업무 기능이 관찰됩니다.', refs,
                 '허용 횟수·단계·최종 상태를 확인하고 경쟁 상태는 동시 실행 근거를 별도로 확보하세요.',
                 '일반 업무 요청 한 건이나 반복 기록만으로 로직 결함·경쟁 상태를 판정하지 않습니다.', surface=True)

    if request.get('kind') == 'multipart' or 'multipart/form-data' in request_mime:
        emit('file_upload', 'multipart_upload_surface', '파일·파트 업로드 입력이 있어 형식·저장·제공 방식의 점검 대상입니다.',
             [href('content-type'), bodyref(request_side=True)], '파일 형식 검사·저장 경로·제공 헤더·실행 권한을 확인하세요.',
             'multipart의 파일 바이트는 저장 형식에서 생략됩니다. 업로드 성공만으로 실행·악성 파일 허용을 판단하지 않습니다.', surface=True)

    if AUTH_PATH.search(path) and any(re.search(r'password|passwd|pwd', f, re.I) for f in fields):
        insecure = urlsplit(r['url']).scheme == 'http'
        emit('authentication', 'plaintext_authentication_transport' if insecure else 'authentication_flow_surface',
             '암호 입력을 포함한 인증 요청이 HTTP 주소로 기록돼 있습니다.' if insecure else '암호 기반 인증 흐름이 관찰됩니다.',
             [reference(r, 'url'), bodyref(request_side=True)], '실제 외부 TLS 경계와 인증·계정 복구 정책을 확인하세요.',
             '내부 TLS 종료 구간일 수 있습니다. 브루트포스·계정 열거·인증 우회는 검사하지 않았습니다.', surface=not insecure)

    cookie = bool(header('cookie'))
    csrf_markers = any(CSRF_FIELD.search(f) for f in fields) or any(CSRF_FIELD.search(h['name']) for h in r.get('headers', []))
    simple = any(x in request_mime for x in ('application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'))
    mutation = r['method'] in ('POST', 'PUT', 'PATCH', 'DELETE') or r.get('context', {}).get('operation') == 'write'
    if cookie and mutation and (simple or r['method'] == 'GET') and not csrf_markers:
        emit('csrf', 'cookie_state_change_surface', '쿠키를 동반한 상태 변경 가능 요청에 저장된 CSRF 표식이 보이지 않습니다.',
             [href('cookie'), href('content-type'), reference(r, 'url')], '실제 상태 변경·SameSite·Origin/Referer 검사·토큰 검증을 확인하세요.',
             '토큰 부재만으로 CSRF를 판단하지 않습니다. 쿠키 속성은 마스킹돼 있고 다른 방어가 있을 수 있습니다.', surface=True)

    origin = header('origin'); acao = header('access-control-allow-origin', True)
    acac = header('access-control-allow-credentials', True).lower() == 'true'
    own_origin = urlsplit(r['url']).scheme + '://' + urlsplit(r['url']).netloc
    if acac and (acao == 'null' or (origin and acao == origin and origin not in (own_origin, '*'))):
        emit('cors', 'credentialed_null_or_reflected_origin', '자격정보 허용과 null 또는 교차 Origin 일치 응답이 함께 관찰됩니다.',
             [href('origin'), href('access-control-allow-origin', True), href('access-control-allow-credentials', True)],
             '해당 Origin이 의도된 신뢰 대상인지와 비공개 응답을 브라우저에서 읽을 수 있는지 확인하세요.',
             '정상 신뢰 Origin일 수 있습니다. 임의 Origin 허용을 증명하지 않습니다. 와일드카드와 자격정보 조합은 성공 근거로 사용하지 않습니다.')

    xfo = header('x-frame-options', True).strip().upper()
    frame_protected = xfo in ('DENY', 'SAMEORIGIN')
    for h in response.get('headers', []):
        if h['name'].lower() != 'content-security-policy': continue  # Report-Only is not enforcement.
        directive = re.search(r'(?:^|;)\s*frame-ancestors\s+([^;]+)', h['value'], re.I)
        if directive:
            sources = directive.group(1).strip().split()
            valid = all(s in ("'self'", "'none'") or re.fullmatch(r'(?:https?://)?(?:\*\.)?[a-z0-9.-]+(?::[0-9*]+)?(?:/[^;]*)?', s, re.I) for s in sources)
            if sources and '*' not in sources and valid: frame_protected = True
    if ok and html and re.search(r'<(?:form|button|input)\b', text, re.I) and not frame_protected:
        emit('clickjacking', 'interactive_html_without_saved_frame_policy', '상호작용 HTML에 저장된 유효 X-Frame-Options·제한적 frame-ancestors가 보이지 않습니다.',
             [bodyref(), href('content-type', True)], '실제 프레임 포함 가능 여부와 민감한 UI 동작을 확인하세요.',
             '헤더 자료가 불완전하거나 별도 제약이 있을 수 있습니다. 기본 CSP·Report-Only 정책은 프레임 차단의 증거로 삼지 않습니다.')

    if (html or script) and re.search(r'location\.(?:search|hash)|document\.(?:URL|referrer)', text):
        sink = re.search(r'document\.cookie\s*=|(?:localStorage|sessionStorage)\.setItem\s*\(|location\.(?:assign|replace)\s*\(', text)
        if sink:
            emit('dom_based', 'dom_source_and_sensitive_sink', '외부 입력 소스와 DOM 저장·이동 처리 지점이 같은 자료에 있습니다.',
                 [bodyref(sink)], '입력의 실제 도달 경로·인코딩·URL 정책을 추적하세요.',
                 '정적 패턴의 동시 등장만 확인했으며 데이터 흐름이나 브라우저 동작은 검증하지 않았습니다.', surface=True)

    websocket = header('upgrade').lower() == 'websocket' and status == 101
    if websocket:
        null_origin = origin == 'null' and cookie
        emit('websockets', 'null_origin_cookie_upgrade' if null_origin else 'websocket_upgrade_surface',
             'null Origin·쿠키를 포함한 WebSocket 업그레이드가 수락된 기록입니다.' if null_origin else 'WebSocket 업그레이드가 있어 메시지 권한 점검 대상입니다.',
             [href('upgrade'), href('origin'), href('cookie')], '핸드셰이크·메시지별 신원·Origin·작업 권한을 확인하세요.',
             '저장 HTTP 자료에는 메시지 프레임·별도 토큰 검증이 없을 수 있습니다. 업그레이드 수락은 탈취 증명이 아닙니다.', surface=not null_origin)

    if not ERRORS['deserialization'].search(text) and any(isinstance(v, str) and re.match(r'^(?:rO0AB|O:\d+:)', v) for _, v in request_leaves):
        emit('deserialization', 'serialized_input_surface', '직렬화 형식으로 보이는 입력이 있습니다.', [bodyref(request_side=True)],
             '서버가 실제로 역직렬화하는지와 허용 타입·무결성 검증을 확인하세요.', '데이터를 역직렬화하거나 객체·가젯을 실행하지 않습니다.', surface=True)
    if any('/__proto__/' in p or '/constructor/prototype/' in p for p, _ in request_leaves) and ok:
        emit('prototype_pollution', 'prototype_property_with_success', '프로토타입 관련 속성 입력에 성공 응답이 저장돼 있습니다.',
             [bodyref(request_side=True), bodyref()], '해당 속성의 병합 경로·프로토타입 변화와 실제 영향 지점을 확인하세요.',
             '일반 속성으로 저장되거나 무시됐을 수 있습니다. 2xx는 프로토타입 오염 증명이 아닙니다.')

    if '/api/' in path.lower() or any(p in ('/openapi', '/swagger') for p, _ in leaves):
        emit('api_testing', 'api_or_schema_surface', 'API 경로 또는 API 명세가 있어 필드·작업별 점검 대상입니다.',
             [reference(r, 'url'), bodyref() if leaves else None], '명세와 실제 기능·허용 필드·작업별 인가 정책을 대조하세요.',
             'API·문서의 존재만으로 과도한 노출이나 대량 할당을 판단하지 않습니다.', surface=True)
    graphql = bool(re.search(r'/(?:graphql|gql)(?:/|$)', path, re.I) or any(p == '/query' and isinstance(v, str) and re.search(r'\b(?:query|mutation)\b|\{', v) for p, v in request_leaves))
    if graphql:
        emit('graphql', 'graphql_operation_surface', 'GraphQL 경로·작업이 관찰됩니다.', [reference(r, 'url'), bodyref(request_side=True)],
             '객체·필드·mutation별 권한과 깊이·비용·배치 제한을 확인하세요.',
             'GraphQL·introspection 사용 자체는 취약점이 아닙니다.', surface=True)
    if (any(p == '/model' for p, _ in request_leaves) and any(p.startswith('/messages/') for p, _ in request_leaves)) or any('/tool_calls/' in p for p, _ in leaves):
        emit('web_llm', 'llm_message_or_tool_surface', '모델 메시지·도구 호출 형식이 있어 LLM 신뢰 경계 점검 대상입니다.',
             [bodyref(request_side=True), bodyref()], '외부 자료·사용자 입력의 도구 권한과 데이터 접근 경계를 확인하세요.',
             '프롬프트 문자열만으로 인젝션 성공을 판단하지 않습니다. 입력 지시문을 실행하거나 다른 모델·도구를 호출하지 않습니다.', surface=True)

    query = dict(parse_qsl(urlsplit(r['url']).query, keep_blank_values=True))
    if 'client_id' in query and 'response_type' in query:
        emit('oauth', 'oauth_authorization_surface', 'OAuth 인가 요청 형식이 있어 리다이렉트·신원 연결 점검 대상입니다.',
             [reference(r, 'url')], 'state·nonce·PKCE·redirect_uri 정책과 계정 연결 흐름을 확인하세요.',
             '단일 요청의 state 부재·암시적 흐름만으로 결함을 단정하지 않습니다. 코드·토큰·쿠키는 마스킹됩니다.', surface=True)
    jwt_config = any(p.lower() in ('/jwt/alg', '/jwt/algorithm') for p, _ in leaves)
    jwks = bool(re.search(r'/(?:jwks(?:\.json)?|\.well-known/jwks\.json)$', path, re.I))
    jwt_js = (html or script) and re.search(r'\bjwtDecode\s*\(|\bjwt-decode\b|\bjsonwebtoken\b', text)
    if jwt_config or jwks or jwt_js:
        emit('jwt', 'jwt_configuration_surface', 'JWT 관련 설정·라이브러리·공개 키 자료가 있어 서명 정책 점검 대상입니다.',
             [reference(r, 'url'), bodyref()], '서버의 알고리즘·서명·키 선택·발급자·대상 검증 정책을 확인하세요.',
             'JWT 원문·서명은 마스킹돼 분석할 수 없습니다. 공개 JWKS·디코딩 라이브러리 자체는 결함이 아닙니다.', surface=True)

    cache_hit = bool(re.search(r'\bHIT\b', header('x-cache', True) + ' ' + header('cf-cache-status', True), re.I) or
                     (header('age', True).isdigit() and int(header('age', True)) > 0))
    host_match = None
    for name in ('x-forwarded-host', 'host'):
        value = header(name).strip()
        try: supplied = urlsplit('//' + value).hostname
        except ValueError: continue
        if not supplied or MASK in value or supplied == urlsplit(r['url']).hostname: continue
        location = header('location', True)
        # A host-shaped string in the redirect/body is a signal, not proof of attacker control.
        if supplied in location or supplied in text:
            host_match = (name, supplied); break
    if host_match:
        name, supplied = host_match
        match = re.search(re.escape(supplied), text)
        refs = [href(name), href('location', True) if supplied in header('location', True) else bodyref(match)]
        emit('host_header', 'alternate_host_reflected', 'URL과 다른 Host 계열 헤더 값이 응답 링크·본문에 반영됩니다.', refs,
             '프록시의 정상 헤더인지와 링크 생성·리다이렉트의 신뢰 정책을 확인하세요.',
             '신뢰 프록시의 정상 동작일 수 있습니다. 임의 Host 허용·계정 탈취는 확인하지 않았습니다.')
        if cache_hit:
            emit('cache_poisoning', 'host_reflection_with_saved_cache_hit', 'Host 계열 입력 반영과 캐시 HIT·Age 단서가 함께 있습니다.',
                 refs + [href(n, True) for n in ('x-cache', 'cf-cache-status', 'age')],
                 '해당 입력이 캐시 키에 포함되는지와 다른 요청에 오염된 응답이 재사용되는지 확인하세요.',
                 '캐시 키·공유 범위·후속 재사용을 검증하지 않았습니다. HIT·반영만으로 오염을 확정하지 않습니다.')
    personal = any(re.search(r'/(?:email|ownerId|owner_id|userId|user_id|password_hash)$', p, re.I) for p, _ in leaves)
    if ok and cache_hit and cookie and personal and re.search(r'\.(?:css|js|png|jpg|svg|ico)$', path, re.I) and ('json' in mime or html):
        emit('cache_deception', 'personal_dynamic_response_on_cached_static_path', '정적 확장자 경로에서 개인 관련 동적 응답·쿠키·캐시 HIT가 함께 관찰됩니다.',
             [reference(r, 'url'), bodyref(), href('cookie')] + [href(n, True) for n in ('x-cache', 'cf-cache-status', 'age')],
             '교차 계정 캐시 키와 경로 해석·개인 응답의 공유 재사용 여부를 확인하세요.',
             '개인별 캐시이거나 공개 자료일 수 있습니다. 다른 사용자의 응답 조회는 수행하지 않았습니다.')
