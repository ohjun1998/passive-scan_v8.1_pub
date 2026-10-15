# v8.6.0 가용성과 기능성 운영 안내

필요한 관찰 기능은 유지하고 반복·폭증·자동 변경 요청을 줄이는 기준으로 변경했습니다. v8.6.0에서는 httpx·Katana도 인증된 로컬 HTTP/HTTPS 게이트웨이를 거쳐 실제 전송 전에 정책과 예산을 검사합니다. 이 도구는 대상 접속이 있는 정찰 도구이며, 가용성 영향을 없애는 도구는 아닙니다. [v8.6 동작과 한계](V86.md)를 함께 확인하세요.

## 유지·조정 기준

| 작업 | 기능상 가치 | 적용한 판단 |
|---|---|---|
| httpx 20개 워커, 각각 `-rl 10 -t 5` | 빠른 생존 확인·기술/서버 식별 | 사용자 지정대로 유지. 재시도·프로토콜 fallback 중복을 제거하고 전송 전 정책·요청/본문 예산과 과부하 감시 적용 |
| Katana의 JS URL 추적 | 아카이브에 없는 현재 엔드포인트 발견 | 유지. 20개 작업 중 최대 2개 동시 실행, 각 `-c 2 -p 1 -rl 2`, 깊이 2, 크롤링 120초, 감독 제한 150초, 응답 읽기 1 MiB |
| JS 다운로드·로컬 정적 분석 | API 경로·메소드·body 필드 발견 | 유지. 작업당 1초 간격, 새 파일 최대 100개, 파일당 2 MiB, 다운로드 총 10 MiB, 성공 캐시 7일 |
| JS 실행 스크린샷 | SPA·현재 UI와 응답의 시각적 관찰 | 유지. 전체 최대 30페이지, 호스트당 2페이지, 페이지당 HTTP 최대 100회, 실행당 최대 1,000회/50 MiB, 최소 0.5초 간격, 응답당 2 MiB |
| GraphQL query POST | POST만 지원하는 조회 API와 SPA 표시 | 정확한 승인 URL을 `--graphql-url`로 지정한 경우만 검토. JSON Content-Type·중복 키·허용 본문 필드·8 KiB·중첩 깊이 10·페이지 크기 100·필드 수·구문 비용을 검사하며 mutation/subscription 차단 |
| 다운로드·export·backup·report 경로 | 노출된 자료·접근 제어 관찰 | 일괄 제거하지 않음. 상태 DB별 호스트당 최대 3회를 전송 전에 예약. httpx·Katana 게이트웨이에도 적용하며 대용량 읽기와 자동 재시도 제한 |
| 사용자가 직접 만든 POST/PUT 등 | 실제 body 값·인증된 기능 관찰 | 수동 브라우저 기록과 Burp/HAR import 유지. 수집한 요청을 자동 재전송하지 않음 |
| 보고서 생성의 재프로빙 | 이미 모은 정보와 중복 | 제거. 저장된 상태만 사용하며 미프로빙을 Dead로 단정하지 않음 |

위 예산은 상태 DB 또는 수집기별입니다. 같은 SQLite 상태 DB를 쓰는 프로세스·스레드는 요청과 읽기 용량을 트랜잭션으로 예약합니다. 서로 다른 GitHub runner의 요청 수·바이트·속도를 하나의 실시간 전역 예산으로 합산하지 않습니다. httpx·Katana의 기본 예산은 상태 DB당 실제 요청 300회·수신 본문 10 MiB이며, 리다이렉트 요청과 오류 응답의 본문도 계산합니다. 입력 URL 한도와 실제 전송 예산은 별개입니다.

## 전체 실행 흐름

1. `TARGET_DOMAINS`를 검증하고 Subfinder 결과를 현재 scope로 묶어 20개 작업에 분배합니다. wildcard를 지정한 경우에만 그 하위 호스트를 포함합니다.
2. Wayback·GAU의 기존 URL을 수집합니다. `balanced`에서 선택한 경우에만 JS 기반 Katana 크롤링과 JS 다운로드·분석을 추가합니다. JS에 들어 있는 필드는 정적 정보이며 실제 body 값과 구분합니다.
3. 모든 URL 후보를 인벤토리에 보존하고, 자동 접속용 목록에는 scope·포트·위험 경로·민감 query 검사를 적용합니다. 제외된 후보는 수동 검토 자료로 남습니다.
4. 선택한 경우 httpx 20개 워커로 GET 프로빙합니다. 기본 작업당 입력 URL 최대 1,000개를 선택하며 `--max-urls`로 선택 한도를 바꿀 수 있습니다. 실제 전송은 상태 DB의 요청·본문 예산을 따릅니다. 선택되지 않았거나 선택 후 전송되지 않은 URL은 `httpx_results_XX.deferred.txt`, 실제 전송과 보류 원인은 `.network.json`에 남깁니다.
5. 성공한 페이지에서 스크린샷 표본을 선택합니다. 익명 브라우저가 JS를 실행하되 HTTP는 보호 전송기를 통해 보내며, 외부 scope와 변경 요청은 차단합니다. 문서 redirect는 새 목적지를 검사한 뒤 다시 탐색합니다.
6. 이전 DB·현재 URL·JS 분석·선택적으로 가져온 실제 요청/응답을 통합하여 Excel/HTML/JSONL/증거 파일을 만듭니다. 보고서 작성은 오프라인입니다. 결과는 기존 방식대로 암호화해 저장합니다.

실제 body 값은 수동 사용 중 관찰한 요청, Burp XML, body를 포함한 HAR에서 얻습니다. URL 발굴만으로 실제 POST body 값을 생성할 수 없습니다.

## 자동 중단과 결과 보존

- 429 또는 503은 즉시 해당 수집기를 중단하며, 제공된 `Retry-After`를 상태에 기록합니다. 시간을 기다렸다가 자동 재시도하지 않습니다.
- 같은 호스트에서 네트워크/서버 오류가 3회 연속 발생하면 중단합니다. 단일 500 응답은 기록하고 수집을 계속할 수 있습니다.
- 호스트별 정상 응답 5개 이상에서 지연 기준을 잡습니다. 지연이 기준 중앙값의 3배이면서 2초를 초과하는 상태가 3회 이어지면 중단합니다. 다른 호스트의 원래 느린 속도를 섞어 판단하지 않습니다.
- httpx/Katana의 게이트웨이는 대상 응답의 상태·시간·오류를 직접 확인하고 중단 상태를 저장합니다. 자식 도구의 출력 감시도 유지합니다. 중단 전에 이미 전송된 요청이나 서버 작업을 되돌릴 수는 없습니다. 게이트웨이가 만든 거부·실패 응답은 대상 서버의 실제 응답으로 가져오지 않습니다.
- Actions matrix는 fail-fast로 다른 작업의 취소를 요청합니다. runner별 취소에는 지연이 있으므로 모든 워커가 동시에 멈추는 실시간 차단기는 아닙니다.
- Python 전송기는 소켓 대기 시간과 응답 읽기 중의 경과 시간을 확인하여 조금씩 계속 도착하는 응답을 무한히 수집하지 않습니다.
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
# 승인된 GraphQL 엔드포인트가 있을 때만 추가 지정
python safe_screenshots.py --active --urls reviewed_pages.txt --scope-file scope.txt --graphql-url https://example.test/graphql
```

## 남는 영향과 기능상 제한

httpx 설정을 유지했으므로 20개 워커가 함께 돌면 명목상 합계 최대 약 200 RPS입니다. 같은 호스트의 URL이 여러 워커에 분산될 수 있습니다. 이 수치는 대상 가용성이나 바운티 프로그램의 허용량을 보장하지 않습니다.

GET 경로명 검사나 GraphQL의 query 구문 검사는 서버 내부 동작을 증명하지 못합니다. 조회처럼 보이는 요청도 로그 기록, 캐시 생성, 비용이 큰 계산이나 잘못 구현된 상태 변경을 유발할 수 있습니다. GraphQL의 비용 제한도 구문과 명시된 페이지 크기를 바탕으로 하므로 알 수 없는 resolver의 실제 비용을 보장하지 않습니다.

httpx·Katana는 인증된 루프백 프록시를 사용하며 HTTPS CONNECT 내부와 리다이렉트의 각 요청에도 전송 전 정책을 적용합니다. 임시 CA는 해당 자식 프로세스에만 전달하고 시스템 인증서 저장소를 변경하지 않습니다. 게이트웨이의 대상 TLS 인증서 검증은 유지하므로 자체 서명 서버의 CA는 실행 환경에서 별도로 신뢰해야 합니다. 이 경계는 통제된 도구가 프록시 옵션을 준수하는 것을 전제로 하며 OS 네트워크 격리는 아닙니다. 이 경로의 TLS·시간 메타데이터는 `protected_gateway`로 표시하며 직접 연결 측정값으로 해석하지 않습니다.

스크린샷의 WebSocket은 실서버에 연결하지 않는 라우팅 모드이므로 실제 실시간 통신 상태를 재현하지 않습니다. 스크린샷의 scope 밖 CDN 차단, 변경 API 차단, 페이지/응답 예산으로 일부 화면은 불완전할 수 있습니다. 로그인 상태나 장시간 작업을 자동 수행하지 않으며, 필요 시 수동 기록/Burp에서 확보합니다. 수동 기록기의 scope는 저장 범위이며 실제 사용자 행동이나 외부 리소스의 전송을 차단하는 규칙이 아닙니다.

다운로드/크롤링 예산과 7일 JS 캐시 때문에 현재 실행에서 확인하지 않은 변경이 있을 수 있습니다. 이전 결과는 역사 자료로 취급하고 새 관찰과 구분합니다. httpx 1.12.0·Katana 1.8.0은 `tools/probe-tools.json`에 버전·배포 ZIP SHA-256을 고정하고 설치 때 확인합니다. CI는 실제 바이너리로 로컬 HTTP/HTTPS 정책을 검증합니다. GAU·Waybackurls·jsluice 등 일부 다른 도구는 여전히 `@latest`를 사용하므로 향후 호환성 확인이 필요합니다.

도구 옵션과 브라우저 제어의 기준 문서: [httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext).
