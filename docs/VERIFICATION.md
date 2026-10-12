# v8.1.1 검증 기록

검증 날짜: 2026-10-12

| 항목 | 결과 |
|---|---|
| Python 3.12 로컬 테스트 | 68개 통과, 실제 Chromium 테스트 1개는 로컬 미설치로 생략 |
| Python/Bash 구문과 diff 공백 검사 | 통과 |
| Actions YAML 구조 | 3개 워크플로 파싱 통과 |
| 보호 정책 | scope·인코딩된 변경 경로·민감 query·페이지 크기 검사, 전송 전 차단 검증 |
| 가용성/기능성 균형 | 다운로드·export·8443·정상 조회·GraphQL query 유지, 단일 500 허용 검증 |
| 과부하 감시 | 429/Retry-After, 3회 연속 오류, 호스트별 지속 지연, 요청/바이트 예산 검증 |
| CLI 감독 | 부분 로그에도 deadline 준수, 마지막 줄바꿈 없는 결과 보존, 중단 전 429 증거 보존 |
| JS 캐시 | 전부 적중하면 추가 요청 0, 만료/실패 기록 처리 검증 |
| 브라우저 정책 | 모의 route에서 scope 밖/변경 요청/위험 redirect 차단, 조회 POST 유지 검증 |
| httpx 설정 | 워커 20개, 각 -rl 10 -t 5 유지 검사 |
| 실제 body 수집 | 기존 Burp/HAR/브라우저 변환·마스킹 테스트 모두 유지 |
| 예제 import/report | 실제 대상 요청 0 |

실제 대상의 스캔·취약점 테스트·POST 재전송·Discord 전송은 수행하지 않았습니다. 실제 Chromium 통합 테스트는 CI의 `browser-fixture` 작업에 추가했으며 루프백 서버에서 JS 렌더링·조회 POST·변경/외부/WebSocket 차단을 검증합니다. 대상 사이트의 의미론적 GET 동작, 원격 Go 수집 도구의 모든 전송과 다중 runner의 즉각적인 동시 중단은 테스트로 보장하지 않습니다. [운영 범위와 남는 제한](AVAILABILITY.md)을 참고하세요.

---

# v8.1.0 검증 기록 (이전 버전)

검증 날짜: 2026-10-12

| 항목 | 결과 |
|---|---|
| Python 3.12.14 단위·통합 테스트 | 40개 통과 |
| Python 전체 구문 컴파일 | 통과 |
| Bash 스크립트 구문 | 통과 |
| GitHub Actions YAML 구조 | 3개 워크플로 파싱 통과 |
| HAR + JS 가상 데이터 import/report | 5개 기록 생성, 네트워크 요청 0 |
| 마스킹 | 가상 Authorization·CSRF 비밀값이 HTML/JSONL/증거 JSON에 남지 않음 |
| HTML 보고서 | JSON 파싱·JavaScript 구문·script 삽입 방어 검증 |
| Excel | 요청·구조 시트, 수식 삽입 방어, 기존 보고서 통합 검증 |
| JS 파이프라인 | 메소드/body 필드/JS 출처 보존과 비-GET 요청의 baseline GET 목록 제외 검증 |
| 기존 global mixer | Katana URL 포함 및 secret finding의 URL 오인 방지 검증 |
| Playwright 요청 변환 | 모의 Request/Response 객체로 실제 body 처리·마스킹·응답 크기 제한 검증 |

실제 대상의 정찰·취약점 테스트·POST 재전송·Discord 전송은 수행하지 않았습니다. Playwright 브라우저 실행과 실제 브라우저에서의 HTML 렌더링은 이 환경에 Chromium이 설치되어 있지 않아 검증하지 못했습니다. Go 수집 도구의 실제 원격 실행과 GitHub Actions의 실행 결과도 이 로컬 검증 범위에 포함되지 않습니다.

GitHub Actions에서도 Python 3.10/3.12/3.13의 단위·통합 테스트와 예제 import/report가 모두 성공했습니다. 원격 실행 기록: https://github.com/ohjun1998/passive-scan_v8.1_pub/actions/runs/38219835792

원본 `passive-scan_v8_pub`의 main은 작업 전후 같은 커밋 `56fe674eff848ba516dc1a743879e43c7cd3a12b`였으며 원본에 쓰기 작업을 수행하지 않았습니다.

`docs/demo-report/index.html`은 가상의 `example.test` 데이터로 생성한 예제 보고서입니다.
