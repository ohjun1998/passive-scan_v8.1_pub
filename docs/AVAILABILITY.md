# v8.1.1 가용성과 기능성 운영 안내

필요한 관찰 기능은 유지하고 반복·폭증·자동 변경 요청을 줄이는 기준으로 변경했습니다. 이 도구는 대상 접속이 있는 정찰 도구이며, 가용성 영향을 없애는 도구는 아닙니다.

## 유지·조정 기준

| 작업 | 기능상 가치 | 적용한 판단 |
|---|---|---|
| httpx 20개 워커, 각각 `-rl 10 -t 5` | 빠른 생존 확인·기술/서버 식별 | 사용자 지정대로 유지. 재시도·프로토콜 fallback 중복을 제거하고 과부하 감시 추가 |
| Katana의 JS URL 추적 | 아카이브에 없는 현재 엔드포인트 발견 | 유지. 20개 작업 중 최대 2개 동시 실행, 각 `-c 2 -p 1 -rl 2`, 깊이 2, 크롤링 120초, 감독 제한 150초, 응답 읽기 1 MiB |
| JS 다운로드·로컬 정적 분석 | API 경로·메소드·body 필드 발견 | 유지. 작업당 1초 간격, 새 파일 최대 100개, 파일당 2 MiB, 다운로드 총 10 MiB, 성공 캐시 7일 |
| JS 실행 스크린샷 | SPA·현재 UI와 응답의 시각적 관찰 | 유지. 전체 최대 30페이지, 호스트당 2페이지, 페이지당 HTTP 최대 100회, 실행당 최대 1,000회/50 MiB, 최소 0.5초 간격, 응답당 2 MiB |
| GraphQL query POST | POST만 지원하는 조회 API와 SPA 표시 | 크기 8 KiB·중첩 깊이 10·페이지 크기 100 등의 조건을 통과한 query만 자동 허용. mutation/subscription 차단 |
| 다운로드·export·backup·report 경로 | 노출된 자료·접근 제어 관찰 | 일괄 제거하지 않음. Python 보호 HTTP를 사용하는 수집에서는 호스트당 최대 3회. 대용량 읽기와 자동 재시도 제한 |
| 사용자가 직접 만든 POST/PUT 등 | 실제 body 값·인증된 기능 관찰 | 수동 브라우저 기록과 Burp/HAR import 유지. 수집한 요청을 자동 재전송하지 않음 |
| 보고서 생성의 재프로빙 | 이미 모은 정보와 중복 | 제거. 저장된 상태만 사용하며 미프로빙을 Dead로 단정하지 않음 |

위 예산은 워커 또는 수집기별입니다. 서로 다른 GitHub runner의 요청 수·바이트·속도를 하나의 실시간 전역 예산으로 합산하지 않습니다. Katana/httpx는 자체 전송기를 사용하므로 Python HTTP의 바이트 예산이나 고비용 경로 3회 제한이 적용되지 않습니다.

## 전체 실행 흐름

1. `TARGET_DOMAINS`를 검증하고 Subfinder 결과를 현재 scope로 묶어 20개 작업에 분배합니다. wildcard를 지정한 경우에만 그 하위 호스트를 포함합니다.
2. Wayback·GAU의 기존 URL을 수집합니다. `balanced`에서 선택한 경우에만 JS 기반 Katana 크롤링과 JS 다운로드·분석을 추가합니다. JS에 들어 있는 필드는 정적 정보이며 실제 body 값과 구분합니다.
3. 모든 URL 후보를 인벤토리에 보존하고, 자동 접속용 목록에는 scope·포트·위험 경로·민감 query 검사를 적용합니다. 제외된 후보는 수동 검토 자료로 남습니다.
4. 선택한 경우 httpx 20개 워커로 GET 프로빙합니다. 기본 작업당 최대 1,000개를 전송하며 나머지는 `httpx_results_XX.deferred.txt`에 남깁니다. 로컬 실행의 `--max-urls`로 변경할 수 있습니다.
5. 성공한 페이지에서 스크린샷 표본을 선택합니다. 익명 브라우저가 JS를 실행하되 HTTP는 보호 전송기를 통해 보내며, 외부 scope와 변경 요청은 차단합니다. 문서 redirect는 새 목적지를 검사한 뒤 다시 탐색합니다.
6. 이전 DB·현재 URL·JS 분석·선택적으로 가져온 실제 요청/응답을 통합하여 Excel/HTML/JSONL/증거 파일을 만듭니다. 보고서 작성은 오프라인입니다. 결과는 기존 방식대로 암호화해 저장합니다.

실제 body 값은 수동 사용 중 관찰한 요청, Burp XML, body를 포함한 HAR에서 얻습니다. URL 발굴만으로 실제 POST body 값을 생성할 수 없습니다.

## 자동 중단과 결과 보존

- 429 또는 503은 즉시 해당 수집기를 중단하며, 제공된 `Retry-After`를 상태에 기록합니다. 시간을 기다렸다가 자동 재시도하지 않습니다.
- 같은 호스트에서 네트워크/서버 오류가 3회 연속 발생하면 중단합니다. 단일 500 응답은 기록하고 수집을 계속할 수 있습니다.
- 호스트별 정상 응답 5개 이상에서 지연 기준을 잡습니다. 지연이 기준 중앙값의 3배이면서 2초를 초과하는 상태가 3회 이어지면 중단합니다. 다른 호스트의 원래 느린 속도를 섞어 판단하지 않습니다.
- httpx/Katana는 출력 감시를 통해 종료합니다. 발견 시점에 이미 전송 중인 요청을 취소하거나 서버 작업을 되돌릴 수 없습니다. 헤더/시간이 출력되지 않는 오류는 정확히 감지하지 못할 수 있습니다.
- Actions matrix는 fail-fast로 다른 작업의 취소를 요청합니다. runner별 취소에는 지연이 있으므로 모든 워커가 동시에 멈추는 실시간 차단기는 아닙니다.
- 일반 예산 소진은 부분 수집으로 끝내며, 과부하 중단은 실패로 표시합니다. 중단 전 출력은 암호화 artifact로 보존하고 가능한 경우 보고서에 통합합니다. 강제 runner 종료나 설치 실패 때에는 결과가 없을 수 있습니다.
- 같은 저장소의 정찰 워크플로는 중복 실행을 대기시킵니다. 서로 다른 저장소·로컬 실행까지 묶는 잠금은 아닙니다.

## 실행 방법

Actions의 `Passive Scan v8.1 · balanced recon` → Run workflow에서 모드를 선택합니다.

| 모드 | 외부 아카이브/제공자 조회 | 대상 접속 | 용도 |
|---|---|---|---|
| balanced (기본) | 수행 | 체크한 크롤링·JS·httpx·스크린샷 수행 | 현재 기능과 엔드포인트를 함께 관찰 |
| passive | 수행 | 크롤링·JS 다운로드·httpx·스크린샷 생략 | 아카이브 URL 발굴 |
| offline | 없음 | 없음 | 예제 import/report와 테스트 |

`balanced`의 네 가지 항목은 기본 활성화되어 있습니다. 필요에 따라 선택을 끌 수 있습니다. 자동 정찰에는 실제 body import와 수동 브라우저 기록이 자동으로 포함되지 않습니다.

로컬 보호 수집의 예:

```bash
python guarded_probe.py --active --input urls.txt --scope-file scope.txt --output results/httpx_results_00.json
python guarded_crawl.py --active --seeds hosts.txt --scope-file scope.txt --output results/example.com_crawl_00.txt
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python safe_screenshots.py --active --urls reviewed_pages.txt --scope-file scope.txt --max-pages 30
```

## 남는 영향과 기능상 제한

httpx 설정을 유지했으므로 20개 워커가 함께 돌면 명목상 합계 최대 약 200 RPS입니다. 같은 호스트의 URL이 여러 워커에 분산될 수 있습니다. 이 수치는 대상 가용성이나 바운티 프로그램의 허용량을 보장하지 않습니다.

GET 경로명 검사나 GraphQL의 query 구문 검사는 서버 내부 동작을 증명하지 못합니다. 조회처럼 보이는 요청도 로그 기록, 캐시 생성, 비용이 큰 계산이나 잘못 구현된 상태 변경을 유발할 수 있습니다. Python HTTP 수집은 요청 전에 검사하지만 Katana 내부의 모든 요청은 Python 정책을 통과하지 않습니다. Katana의 native scope/exclusion과 출력 후 감시를 사용하며 redirect·복잡한 인코딩의 모든 경우를 보장하지 않습니다. 엄격한 전송 전 검사가 필요한 수집에는 `crawl_safe.py`를 사용할 수 있으며 이 경우 JS 기반 URL 추적은 줄어듭니다.

스크린샷의 scope 밖 CDN 차단, 변경 API 차단, 페이지/응답 예산으로 일부 화면은 불완전할 수 있습니다. 로그인 상태나 장시간 작업을 자동 수행하지 않으며, 필요 시 수동 기록/Burp에서 확보합니다. 수동 기록기의 scope는 저장 범위이며 실제 사용자 행동이나 외부 리소스의 전송을 차단하는 규칙이 아닙니다.

다운로드/크롤링 예산과 7일 JS 캐시 때문에 현재 실행에서 확인하지 않은 변경이 있을 수 있습니다. 이전 결과는 역사 자료로 취급하고 새 관찰과 구분합니다. 외부 도구는 `@latest`로 설치하므로 향후 버전 변경 시 옵션 호환성을 다시 확인해야 합니다.

도구 옵션과 브라우저 제어의 기준 문서: [httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext).
