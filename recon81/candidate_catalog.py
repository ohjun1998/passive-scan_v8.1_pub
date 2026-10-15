"""Locally versioned Academy topic mapping, checked against official pages 2026-10-15."""
BASE_KINDS = {'idor', 'authorization', 'xss', 'sqli', 'sensitive_data', 'credential_exposure'}
# Labels are project UI labels, not copied issue definitions or Burp Scanner checks.
_ENTRIES = [
    ('idor', 'IDOR', 'access-control', '소유권·신원·객체 접근 정책'),
    ('authorization', '인가·권한', 'access-control', '실제 계정 권한·접근 정책'),
    ('xss', 'XSS', 'cross-site-scripting', '출력 문맥·인코딩·브라우저 실행'),
    ('sqli', 'SQLi', 'sql-injection', '입력 변화와 쿼리 동작의 연관'),
    ('sensitive_data', '민감정보', 'information-disclosure', '필드별 공개·제공 정책'),
    ('credential_exposure', 'API KEY·TOKEN·비밀값', 'information-disclosure', '공개 식별자 여부·노출 범위'),
    ('authentication', '인증', 'authentication', '신원·인증 흐름·외부 TLS 경계'),
    ('path_traversal', '경로 탐색', 'file-path-traversal', '파일 경계·실제 반환 파일'),
    ('command_injection', 'OS 명령어 주입', 'os-command-injection', '입력이 명령 실행에 미치는 영향'),
    ('business_logic', '비즈니스 로직', 'logic-flaws', '허용 업무 규칙·다단계 상태 변화'),
    ('information_disclosure', '상세 오류·내부 정보 노출', 'information-disclosure', '오류의 실제 출처·공개 정책'),
    ('file_upload', '파일 업로드', 'file-upload', '저장 위치·형식 검사·다운로드·실행 여부'),
    ('race_conditions', '경쟁 상태', 'race-conditions', '동시 요청·시간 순서·불변식·최종 상태'),
    ('ssrf', 'SSRF', 'ssrf', '서버 측 접속 여부·목적지 허용 정책'),
    ('xxe', 'XXE', 'xxe', 'XML 파서·외부 엔티티 처리'),
    ('nosql_injection', 'NoSQL 주입', 'nosql-injection', '연산자·입력 타입·쿼리 동작'),
    ('api_testing', 'API 점검', 'api-testing', '노출 명세·필드 권한·업무 정책'),
    ('cache_deception', '웹 캐시 속임', 'web-cache-deception', '인증별 캐시 키·정적 경로 처리·교차 계정 재사용'),
    ('csrf', 'CSRF', 'csrf', '상태 변경·SameSite·Origin 검사·토큰 검증'),
    ('cors', 'CORS', 'cors', '허용 Origin 정책·자격정보·비공개 데이터'),
    ('clickjacking', '클릭재킹', 'clickjacking', '실제 프레임 허용·민감한 UI 동작'),
    ('dom_based', 'DOM 기반 취약점', 'dom-based', '소스에서 처리 지점까지 실제 데이터 흐름'),
    ('websockets', 'WebSocket 점검', 'websockets', '핸드셰이크 신원·Origin·메시지 권한'),
    ('deserialization', '안전하지 않은 역직렬화', 'deserialization', '실제 역직렬화 경로·허용 타입'),
    ('web_llm', '웹 LLM 점검', 'llm-attacks', '모델 입력·도구 권한·외부 데이터 신뢰 경계'),
    ('graphql', 'GraphQL 점검', 'graphql', '작업·필드별 권한·리소스 제한'),
    ('ssti', '서버 템플릿 주입', 'server-side-template-injection', '입력의 템플릿 해석·서버 실행'),
    ('cache_poisoning', '웹 캐시 오염', 'web-cache-poisoning', '입력 반영·캐시 키·다른 요청의 재사용'),
    ('host_header', 'HTTP Host 헤더', 'host-header', '헤더 신뢰 경계·링크 생성·리다이렉트'),
    ('request_smuggling', 'HTTP 요청 스머글링', 'request-smuggling', '원시 바이트·프로토콜·프런트/백엔드 파싱'),
    ('oauth', 'OAuth 인증', 'oauth', 'state·nonce·PKCE·redirect_uri와 신원 연결'),
    ('jwt', 'JWT 점검', 'jwt', '마스킹 전 안전 메타데이터·서버 서명 검증 정책'),
    ('prototype_pollution', '프로토타입 오염', 'prototype-pollution', '객체 병합·프로토타입 변화·영향 처리 지점'),
]
_SURFACE_ONLY = {'file_upload', 'race_conditions', 'api_testing', 'csrf', 'dom_based', 'web_llm', 'graphql', 'oauth', 'jwt'}
_BOTH = {'authentication', 'path_traversal', 'business_logic', 'ssrf', 'xxe', 'websockets', 'deserialization'}
CATALOG = {key: {'kind': key, 'label': label, 'topic': topic,
    'source_url': 'https://portswigger.net/web-security/' + topic,
    'required_followup': followup,
    'assessment_mode': ('additional_capture_required' if key == 'request_smuggling' else 'surface_only' if key in _SURFACE_ONLY else
                        'signal_and_surface' if key in _BOTH else 'saved_signal')}
    for key, label, topic, followup in _ENTRIES}
KINDS = {key: entry['label'] for key, entry in CATALOG.items()}
CATALOG_VERSION = '8.8.0-1'
CATALOG_CHECKED_AT = '2026-10-15'
CATALOG_SOURCE = 'https://portswigger.net/web-security/all-topics'
