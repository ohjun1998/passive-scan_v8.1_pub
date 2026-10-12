# v8.1.0 검증 기록

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

CI에는 Python 3.10/3.12/3.13 검증을 설정했습니다. 이 기록에서 해당 원격 CI가 이미 통과했다고 주장하지 않습니다.

원본 `passive-scan_v8_pub`의 main은 작업 전후 같은 커밋 `56fe674eff848ba516dc1a743879e43c7cd3a12b`였으며 원본에 쓰기 작업을 수행하지 않았습니다.

`docs/demo-report/index.html`은 가상의 `example.test` 데이터로 생성한 예제 보고서입니다.
