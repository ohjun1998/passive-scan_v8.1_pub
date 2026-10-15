# v8.5.2 (2026-10-15)

- CLI 무이벤트 시간 초과와 모델 첫 응답 지연을 구분하고 doctor·배치 실패 기록에 안전한 수치만 보존.
- 제공된 Community Security Lab 3.4.0 전용 loopback 재현기 추가. 별도 CookieJar 신원·실제 비공개 본문·허용/거부 및 수정 경로 대조.
- 새 로컬 요청 61건, 권한 50표본, 5자원 비인가 반환 13표본 및 SQL·내부 예외 노출 재현. 수정 경로 25/25 정책 일치.
- 신규 회귀 테스트 7개 포함 로컬 165개 중 163개 통과, 선택 Chromium 2개는 CI에서 검증.
- 실제 CLI probe는 CLI_EVENT_TIMEOUT/실행 이벤트 0건. 모델 완료 0/22·실제 모델 평가는 계속 미완료. Pro 확인은 완료 조건에서 제외.
- [실행·재현 안내](docs/V852.md) · [남은 단계](docs/REMAINING_STEPS.md) · [유스케이스](docs/USE_CASES.md).

# v8.5.1 (2026-10-15)

- `doctor` 실행 전 진단 및 선택적 증거 없는 모델 연결 시험, 안전한 JSON 진단 저장.
- CLI 없음과 완료 결과 파일 누락을 구분하고 첫 응답 제한을 `--first-response-timeout`으로 지정.
- 배치 시도 기록에 시간 제한·모델 ID를 보존. 기존 명시적 재시도와 최대 3회 제한 유지.
- 집계 보고서의 Codex 실행 확인·수동/미검증·미완료 건수를 표시하고 평가 결과에 실행 출처 연결.
- 기존 실습 증거 77건의 파일 해시 104개 확인, 22패킷·신원 4개·정책 50개·평가 라벨 50개 준비.
- 실제 연결 시험은 FIRST_RESPONSE_TIMEOUT. 실제 모델 평가·새 재현은 미완료로 기록.
- [실행 안내](docs/V851.md) · [남은 단계](docs/REMAINING_STEPS.md) · [유스케이스](docs/USE_CASES.md).

# v8.5.0 (2026-10-14)

- 자원별 패킷·원본 JSON pointer/텍스트 fragment로 긴 증거를 분할하고 누락·부분 검토를 표시.
- 신원 응답의 실제 ID/역할과 출처 있는 기대 권한 연결. 세션 독립 검증은 false 유지.
- v8.5 structured citations의 실제 위치·발췌 검사. 구형 결과는 legacy_unverified로 구분.
- 첫 응답/전체 실행/출력 한도·안전한 단계별 실패 코드, 완료 결과 재검증·재개, 명시적 실패 재시도·시도 상한·쓰기 잠금.
- fragment별 진단 상태, 독립 정답 라벨의 오탐/누락/보류 평가, 한국어 PDF 내보내기.
- [실행 안내](docs/V85.md), [전체 시간순 흐름](docs/FLOW_V85.md), [유스케이스](docs/USE_CASES.md).

# v8.4.1 (2026-10-14)

- 현재 v8.2 기반으로 AI 검토 실행 코드를 통합. 이전 v8.4 개발본 전체 복원은 아님.
- ai_review.py prepare/import/codex, scope·마스킹·예산 제한 증거 패킷, strict JSON 검증, 별도 HTML/Markdown/JSON 및 실행 기록.
- API 과다 노출·JS/HTML 비밀정보·오류 내부정보 프롬프트를 실제 make_prompt에 적용.
- 기본 보고서 요청·분석 해시 manifest 추가. 수동 import와 CLI 실행 확인을 구분하고 사람 확정 요구.
- [실행 안내](docs/V84.md), [전체 흐름](docs/FLOW_V84.md), [유스케이스](docs/USE_CASES.md).

# 변경 이력

## 8.2.0

- [신규·개선·유지 유스케이스 다이어그램](docs/USE_CASES.md)과 [v8.2 운영 안내](docs/V82.md).
- 계정·조직·기능·capture·기대 권한 라벨과 이전 관찰 ID 호환.
- 증거 기반 우선순위·정확한 자원/전체 payload의 계정 응답 비교.
- 기능 흐름 추정·미수집/미검토 커버리지·검토 상태와 근거 저장.
- 응답 비교의 배열 후반 값·빈 객체/배열·타입·폼 중복 필드 보존, 복잡도 초과 표시.
- OpenAPI/Swagger·HTML form 로컬 가져오기, 외부 ref/폼 제출 없음.
- JS 내용/분석기 해시 캐시·추출 재사용·추가/제거 endpoint와 조건부 재확인.
- 선택한 조회 baseline 큐와 별도 예산·scope·전송 정책·런타임 인증정보 마스킹.
- GraphQL AST 기반 operation/fragment/깊이/alias/페이지 크기 제한.
- httpx 20개 워커·각 -rl 10 -t 5와 원본 v8 저장소 유지.

## 8.1.1

- 가용성과 수집 기능을 함께 고려한 balanced/passive/offline 실행 모드.
- httpx 20개 워커와 각 `-rl 10 -t 5` 유지. 입력 정책, 응답 크기·작업 시간 제한, 과부하 중단, 자동 재시도 제거.
- Katana JS 크롤링 유지. 명시적 scope·위험 경로 제외·동시 실행/깊이/시간/응답 크기 제한.
- JS 다운로드 속도·개수·바이트·디스크 예산과 성공한 다운로드의 7일 캐시. 캐시 전체 적중 시 재다운로드하던 동작 제거.
- JS 렌더링을 유지하는 스크린샷 표본 수집. HTTP 요청마다 정책·예산 검사, 제한된 GraphQL query POST 지원, 변경 요청·WebSocket·서비스 워커 차단.
- 단일 5xx나 서로 다른 호스트의 속도 차이 때문에 수집을 중단하지 않도록 호스트별 지연/오류 판단.
- 보고서 생성의 추가 네트워크 요청 제거, 미프로빙 상태 구분, 중단 전 부분 결과 보존.
- 쉘의 URL 문자열 실행 제거, 워크플로 중복 실행 방지, 중단 후 자동 재개·재촬영 제거.
- 오프라인 보호 기능 테스트와 로컬 서버에 대한 실제 Chromium 통합 테스트 추가.

## 8.1.0

- Burp Save items XML / HAR / JSONL / URL 목록을 로컬 인벤토리로 통합.
- 실제 body와 정적 body 필드를 구분하고 HTTP 메소드를 보존.
- JSON·폼·XML/SOAP·multipart의 body 파싱과 민감값 마스킹.
- 요청 구조, 요청 값 변형, 응답 변형에 대한 개별 ID와 SQLite 저장.
- 검색 가능한 단일 HTML, 증거 JSON, Excel, 실행 차단된 Postman 컬렉션.
- 수동 Playwright 브라우저 트래픽 기록과 scope 필터.
- 원본 JS URL 매핑, URL 해시 파일명, 제한된 JS 다운로드·redirect scope 검증.
- Katana URL을 global mixer에 포함. TruffleHog 결과를 URL 후보로 취급하던 처리 제거.
- TruffleHog 키 유효성 외부 검증 비활성화와 비밀값 출력 마스킹.
- 기존 Gemini API 연동 제거. Discord 배송은 명시적으로 활성화한 경우에만 수행.
- 기존 URL 리포트에 v8.1 요청/구조 시트를 추가. 원본 저장소와 분리.
