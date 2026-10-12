# 변경 이력

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
