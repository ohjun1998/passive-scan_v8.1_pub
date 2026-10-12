# v8.2.0 검증 기록

검증 날짜: 2026-10-12

| 항목 | 결과 |
|---|---|
| Python 3.12 단위·통합 테스트 | 103개 통과; 실제 Chromium 테스트 2개는 별도 환경 필요로 생략 |
| GitHub CI Python 3.10 / 3.12 / 3.13 | 각 103개 통과, 브라우저 테스트는 별도 작업 |
| 실제 Chromium | 2개 통과: 대시보드 계정 필터·비교·검토 내보내기, 조회 POST 유지·변경/외부/WebSocket 차단 |
| 게시 파일 검증 | 소스·테스트·예제·문서를 로컬 blob SHA와 대조 |
| 전체 유스케이스 | GitHub Mermaid 렌더링 확인, 신규/개선/유지 색상·문구 구분 |
| Python/Bash 구문과 diff 공백 | 통과 |
| Actions YAML 구조 | 3개 워크플로 파싱 통과 |
| 합성 데이터 import/report/queue | 5개 기록, 계정 비교 1쌍, 기능 흐름 3그룹, 대상 추가 요청 0 |
| 기존 DB/관찰 ID 호환 | 라벨 없는 v8.1 ID 유지, DB 테이블 추가·재가져오기 검증 |
| 계정 비교 | 동일 자원/메소드/전체 body 비교, 다른 ID·미완전 body 제외 |
| 응답 비교 정확성 | 배열 후반 값, 빈 객체/배열, 타입, 점이 들어간 키, 폼 중복 필드, 복잡도 초과 표시 |
| 검토 상태 | 증거 메모 필요, 기존 ID 검사, 일괄 변경 실패 시 롤백 |
| OpenAPI/폼 | 로컬 ref·순환 제한, 외부 ref 요청 없음, 비밀 예시값·자동 제출 없음 |
| JS 분석 캐시 | 내용/분석기 해시, 추출 재사용, 추가/제거 구조, 304 조건부 재확인 모의 검증 |
| 선택적 조회 큐 | 첫 요청 전 전체 ID/scope/메소드 검증, 큐 변조 차단, 런타임 비밀 마스킹 |
| 루프백 HTTP baseline | 실제 로컬 서버 2회 조회, redirect 자동 추적 없음 |
| GraphQL AST | operation 선택·fragment 순환·alias·페이지 크기 제한, mutation 우회 차단 |
| httpx 설정 | 20개 워커와 각 -rl 10 -t 5 유지 테스트 통과 |

실제 대상 스캔·취약점 테스트·운영 대상 POST 재전송은 수행하지 않았습니다. Chromium 설치 파일이 이 환경에서 정상 ZIP으로 제공되지 않아 실제 브라우저 테스트 2개는 실행하지 못했습니다. 이후 사용자의 업로드 승인으로 v8.2를 게시했고 GitHub CI의 실제 Chromium 테스트 2개가 통과했습니다. 본문 차이와 후보 점수는 취약점 판정이 아닙니다.

원격 검증: [Python 세 버전과 실제 Chromium 성공](https://github.com/ohjun1998/passive-scan_v8.1_pub/actions/runs/38247977132). 검증 소스 커밋: `8c4d514b9881a65ec3ccb19429c41ce01471b5a9`. Python CI 로그는 각 `Ran 105 tests, OK (skipped=2)`, 별도 Chromium 로그는 `Ran 2 tests, OK`입니다.

원본 v8 main은 `56fe674eff848ba516dc1a743879e43c7cd3a12b`로 유지되어 있습니다. 전체 프로세스와 향후 변경 강조 기준을 문서 및 `AGENTS.md`에 저장했습니다.

[사용법](V82.md) · [유스케이스](USE_CASES.md)

---

# v8.1.1 검증 기록

검증 날짜: 2026-10-12

| 항목 | 결과 |
|---|---|
| Python 3.12 로컬 테스트 | 69개 통과, 실제 Chromium 테스트 1개는 로컬 브라우저 설치 실패로 생략 |
| GitHub CI Python 3.10 / 3.12 / 3.13 | 각 69개 통과 (브라우저 테스트는 별도 작업) |
| 실제 Chromium + 루프백 서버 | 1개 통과: JS 렌더링·조회 POST 유지, 변경/외부/WebSocket 전송 차단 |
| Python/Bash 구문과 diff 공백 검사 | 통과 |
| Actions YAML 구조 | 3개 워크플로 파싱 통과 |
| 보호 정책 | scope·인코딩된 변경 경로·민감 query·페이지 크기 검사, 전송 전 차단 검증 |
| 가용성/기능성 균형 | 다운로드·export·8443·정상 조회·GraphQL query 유지, 단일 500 허용 검증 |
| 과부하 감시 | 429/Retry-After, 3회 연속 오류, 호스트별 지속 지연, 요청/바이트 예산과 trickle 응답 전송 제한 검증 |
| CLI 감독 | 부분 로그에도 deadline 준수, 마지막 줄바꿈 없는 결과 보존, 중단 전 429 증거 보존 |
| JS 캐시 | 전부 적중하면 추가 요청 0, 만료/실패 기록 처리 검증 |
| 브라우저 정책 | 모의 route에서 scope 밖/변경 요청/위험 redirect 차단, 조회 POST 유지 검증 |
| httpx 설정 | 워커 20개, 각 -rl 10 -t 5 유지 검사 |
| 실제 body 수집 | 기존 Burp/HAR/브라우저 변환·마스킹 테스트 모두 유지 |
| 예제 import/report | 실제 대상 요청 0 |

실제 대상의 스캔·취약점 테스트·POST 재전송·Discord 전송은 수행하지 않았습니다. 실제 Chromium 통합 테스트는 CI의 `browser-fixture` 작업에서 통과했습니다. 루프백 서버에 도달한 요청을 검사하여 JS 렌더링·조회 POST·변경/외부/WebSocket 차단을 확인했습니다. WebSocket 콜백의 동기 close 정체도 실제 브라우저에서 발견해 수정했습니다. 대상 사이트의 의미론적 GET 동작, 원격 Go 수집 도구의 모든 전송과 다중 runner의 즉각적인 동시 중단은 테스트로 보장하지 않습니다. [운영 범위와 남는 제한](AVAILABILITY.md)을 참고하세요.

원격 검증 기록: [69개 단위·통합 테스트와 별도 Chromium 테스트](https://github.com/ohjun1998/passive-scan_v8.1_pub/actions/runs/38230437231). 검증 소스 커밋: `f1972603b21b21275e2a62becd482739a3708bef`.

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
