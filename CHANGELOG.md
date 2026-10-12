# 변경 이력

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
