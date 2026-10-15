# Passive Scan v8.5.2

URL 목록과 실제 HTTP 요청/응답을 함께 관리하는 버그바운티 정찰 도구입니다.

원본 `ohjun1998/passive-scan_v8_pub`의 커밋 `56fe674eff848ba516dc1a743879e43c7cd3a12b`를 복사해 만든 별도 프로젝트입니다. 원본 저장소를 수정하거나 원본에서 스캔을 실행하지 않습니다.

현재 버전은 **8.5.2**입니다. [실행·로컬 재현 안내](docs/V852.md) · [남은 단계](docs/REMAINING_STEPS.md) · [전체 흐름도](docs/FLOW_V85.md). CLI 실행 이벤트 미도착과 첫 모델 응답 지연을 구분합니다. 제공된 Community Security Lab의 로컬 재현기로 새 요청 61건·권한 50표본을 확인했고, 수정 경로 25/25가 정책과 일치했습니다. ChatGPT 로그인 Codex CLI면 충분하며 Pro 등급 확인은 완료 조건이 아닙니다.

v8.5에서 자원별 증거 분할·검증된 재개·단계별 실패 기록·신원/정책 연결·실제 인용 검사·커버리지·평가·PDF 내보내기를 추가했습니다. [v8.5 실행 안내](docs/V85.md). 실제 자동 모델 실행은 현재 환경에서 CLI 실행 이벤트가 없어 미완료이며, 준비한 22패킷을 검토 완료로 표시하지 않습니다.

v8.4.1에서 저장 증거 기반 AI 검토의 prepare/import 및 선택적 Codex CLI 실행 경로와 정보 노출 검토 프롬프트를 추가했습니다. [v8.4.1 실행 안내](docs/V84.md) · [URL 수집부터 끝까지의 흐름도](docs/FLOW_V84.md) · [GitHub 과정](docs/GITHUB_PROCESS.md).

v8.2에서 추가한 기능으로, 계정·조직·기능 라벨, 증거 기반 후보 우선순위, 계정별 응답 비교, 기능 흐름과 진단 커버리지 대시보드를 추가했습니다. JS 변경분과 저장된 OpenAPI/HTML form도 분석합니다. 수집과 분석 기능, **httpx 20개 워커, 각각 `-rl 10 -t 5`**는 유지합니다.

[v8.2 사용법과 제한](docs/V82.md) · [신규·개선·유지 유스케이스 다이어그램](docs/USE_CASES.md) · [가용성·기능성 운영 안내](docs/AVAILABILITY.md)

## v8.2에서 달라진 점

| 기능 | 처리 방식 |
|---|---|
| 계정·기능 라벨 | 마스킹된 세션과 별도로 계정·조직·기능·기대 권한 보존 |
| 후보 우선순위 | 실제 필드·응답·기능 맥락의 근거와 부족한 정보 제시 |
| 계정 비교 | 동일 자원·메소드·payload의 계정별 응답 차이 표시 |
| 커버리지·흐름 | 미수집/미검토 구분, 업로드→조회 같은 값 연결 추정 |
| 검토 상태 | 증거 메모와 함께 상태 변경·JSON 내보내기/DB 반영 |
| JS·명세 분석 | 해시/분석기 버전 캐시, 변경 endpoint, OpenAPI/HTML form 필드 |
| 선택적 조회 baseline | CLI에서 명시적으로 고른 실제 요청만 별도 예산으로 조회 |

후보 점수와 응답 차이는 취약점 판정이 아닙니다. 분석·가져오기·보고서는 대상 추가 요청 없이 수행됩니다. 조회 baseline은 `--active`와 선택한 ID가 있어야 실행됩니다.

## v8.1에서 달라진 점

| 기능 | 처리 방식 |
|---|---|
| Burp XML 가져오기 | Save items XML의 URL·메소드·헤더·body·응답을 수집 |
| HAR 가져오기 | 브라우저가 기록한 실제 요청 body와 응답 수집 |
| 브라우저 기록 | Playwright 창에서 사용자가 직접 실행한 기능의 트래픽을 기록 |
| JS 분석 | jsluice의 method·headers·bodyParams와 JS 출처 보존 |
| body 파싱 | JSON·배열·폼·XML/SOAP·multipart 지원 |
| 중복 관리 | 메소드·전체 경로·query 필드·body 필드로 구조를 묶고 실제 값 변형·응답 변형을 별도로 보존 |
| 보고서 | 검색 가능한 단일 HTML, JSONL, 증거 JSON, Excel, 검토 전용 Postman |
| 비밀정보 | Authorization·Cookie·비밀번호·토큰·API 키 등 저장 전 마스킹 |
| 외부 AI 호출 | v8.1 기본 경로에서 제거. v8.4.1은 사용자가 ai_review.py를 실행하거나 ChatGPT에 패킷을 제공할 때 선택 증거를 모델에 전달 |

**URL만 발견한 경우 메소드는 UNKNOWN입니다. JS에서 발견한 필드명은 실제 body 값으로 표시하지 않습니다.**

기존 URL 발굴 작업에는 네트워크 요청이 발생합니다. Katana 크롤링, httpx GET 프로빙, JS 다운로드, 스크린샷은 대상에 접속합니다. `request_inventory.py`의 import/report 작업은 로컬 파일만 처리합니다. 기본 수집 파이프라인은 기록한 요청을 재전송하지 않습니다. 별도 `review_queue.py`는 명시적으로 선택한 GET/HEAD 또는 검토한 조회 POST만 실행합니다.

## 설치와 빠른 확인

Python 3.10 이상이 필요합니다. Windows에서도 오프라인 가져오기·보고서 기능을 사용할 수 있습니다. 기존 Bash 정찰 스크립트는 Linux/WSL/GitHub Actions에서 실행합니다.

```bash
python -m pip install -r requirements-v81.txt
python request_inventory.py import examples/v82-demo.jsonl --scope example.test
python request_inventory.py report --xlsx
```

`reports/requests/index.html`을 브라우저에서 열면 메소드·출처·관찰 상태별 필터와 body 값 검색을 사용할 수 있습니다. 테이블에서 요청을 선택하면 요청/응답 내용을 확인할 수 있습니다. 예제는 가상의 `example.test` 트래픽이고 실제 접속은 없습니다.

## 1. Burp의 실제 요청/응답 가져오기 — 권장

1. Burp 브라우저에서 테스트 계정으로 로그인하고 대상 기능을 직접 사용합니다.
2. HTTP history에서 범위 내 항목을 선택합니다.
3. 우클릭 → **Save items**로 XML을 저장합니다. 가능하면 요청/응답 Base64 인코딩을 선택합니다.
4. 파일을 `imports/burp.xml`처럼 저장한 뒤 가져옵니다. `imports/`는 Git에 포함되지 않습니다.

```bash
python request_inventory.py import imports/burp.xml --scope example.com
python request_inventory.py report --xlsx
```

여러 출처 파일은 한 번에 통합할 수 있습니다.

```bash
python request_inventory.py import imports/burp.xml imports/browser.har --scope example.com --scope api.example.com
```

서브도메인을 포함하는 scope는 따옴표로 감쌉니다.

```bash
python request_inventory.py import imports/burp.xml --scope "*.example.com"
```

현재 Burp **Save items** XML을 지원합니다. Scanner issue XML과 Burp 프로젝트 바이너리는 직접 가져오지 않습니다. XML의 외부 DTD·엔티티는 허용하지 않습니다. Burp의 표준 내부 ELEMENT/ATTLIST DTD는 제거한 뒤 파싱합니다.

## 2. 브라우저 HAR 가져오기

개발자 도구 → Network에서 **Preserve log**를 켜고 대상 기능을 사용한 뒤 요청 내용을 포함하는 HAR로 내보냅니다. 브라우저/내보내기 옵션에 따라 body가 생략될 수 있습니다. 이 경우 `body_not_captured`로 표시하며 값을 임의로 만들지 않습니다.

```bash
python request_inventory.py import imports/browser.har --scope example.com
python request_inventory.py report --xlsx
```

## 3. Playwright로 직접 사용한 기능 기록하기

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python record_browser.py --url https://example.com --scope example.com --scope api.example.com --seconds 300
python request_inventory.py report --xlsx
```

브라우저 창에서 직접 로그인하고 조회·수정 등의 기능을 사용합니다. 자동 로그인·자동 폼 제출·요청 재전송은 수행하지 않습니다. scope 밖 트래픽은 저장하지 않으며, 실제 브라우저는 정상 페이지 로딩을 위해 외부 리소스를 요청할 수 있습니다. 서비스 워커는 차단합니다. 브라우저에 입력한 요청 자체는 정상적으로 서버에 전송됩니다.

이 기록기는 Content-Length가 명시된 1 MiB 이하의 구조화된 응답 body만 읽습니다. 길이를 알 수 없는 응답은 메타데이터만 기록합니다. 누락 없는 트래픽 수집이 필요하면 Burp XML을 사용하세요. WebSocket 메시지와 앱/서비스 워커에서만 발생하는 트래픽은 이 버전의 수집 대상이 아닙니다.

## 4. JS 요청 구조 보존

기존 파이프라인에서 `scan_linkfinder.sh`가 jsluice 결과를 JSONL로 보존합니다.

```bash
bash scan_linkfinder.sh 00
python collect_request_inventory.py --scope-file targets.txt --xlsx
```

직접 분석한 jsluice JSONL도 가져올 수 있습니다.

```bash
jsluice urls main.js > imports/main-js.jsonl
python request_inventory.py import imports/main-js.jsonl --format jsluice --base-url https://example.com/static/main.js --scope example.com
```

JS URL을 기준으로 상대 경로를 해석합니다. 런타임의 API base URL이나 SPA에서 현재 문서 경로를 기준으로 해석되는 상대 경로는 실제 트래픽과 대조해야 합니다. 동적 변수·wrapper 함수·암호화된 payload는 정적 분석으로 실제 값을 확보할 수 없습니다.

jsluice 원본 JSONL에는 JS에 들어 있는 비밀값이 포함될 수 있으므로 원본을 Git에 올리지 마세요. 자동 파이프라인은 원본 JSONL을 디스크에 남기지 않고 마스킹된 레코드로 변환합니다. JS 파일명은 URL 해시로 생성하여 다른 경로의 `main.js`가 덮어쓰이지 않게 했습니다.

## 출력과 데이터 구조

| 파일 | 용도 |
|---|---|
| `reports/request_inventory.sqlite3` | 로컬 요청/응답 인벤토리, 동일 관찰의 횟수·최초/최근 수집 시각 |
| `reports/requests/index.html` | 네트워크 연결 없이 열 수 있는 단일 HTML 보고서 |
| `reports/requests/requests.jsonl` | 다른 도구와 연동할 구조화된 기록 |
| `reports/requests/evidence/*.json` | 요청/응답별 마스킹된 증거 |
| `reports/requests/request_inventory.xlsx` | `--xlsx` 지정 시 생성되는 Excel |
| `reports/requests/postman_review.json` | 메소드/body를 보존한 검토 전용 컬렉션 |

`observed=true`는 실제 요청에서 확보한 기록입니다. `observed=false`는 URL 목록이나 JS의 정적 추출 결과입니다. `body.complete`는 body 수집/표현의 완전성을 나타내며 마스킹 여부와 별개입니다. 요청·응답은 정규화되므로 원본 패킷 바이트와 다릅니다. 압축 헤더·길이 헤더는 정규화된 패킷에서 제거합니다.

`structure_id`는 요청 구조를 묶습니다. `request_id`는 마스킹 후 URL·메소드·헤더·body의 값 변형을 구분합니다. `observation_id`는 응답·출처까지 구분합니다. 서로 다른 인증 토큰 자체는 동일한 마스킹 값이 될 수 있으므로 `--actor`·`--tenant` 라벨로 구분합니다. 라벨은 사용자가 제공한 맥락이며 실제 로그인 계정을 자동 인증하지 않습니다. 응답 차이는 별도 기록으로 남깁니다.

Postman 컬렉션은 collection-level pre-request script로 실행을 차단합니다. 실제 요청을 보내려면 복사본에서 차단 스크립트를 직접 제거하고 세션·body·scope를 검토해야 합니다. UNKNOWN 메소드는 실제 메소드를 확인한 뒤 바꾸세요. multipart 파일 바이트는 포함되지 않습니다.

## 민감정보와 제한

- 알려진 민감 필드와 일반적인 토큰 패턴을 마스킹합니다. 임의 이름의 비밀값·개인정보를 완벽히 식별하는 기능은 아니므로 공유 전에 확인해야 합니다.
- 구조화되지 않은 text/HTML은 기본적으로 body를 생략합니다. 꼭 필요한 경우 `--include-text`로 보존할 수 있지만 마스킹은 최선 노력 방식입니다.
- multipart는 텍스트 필드값과 파일명·크기를 저장하고 파일 바이트는 생략합니다.
- body는 최대 1 MiB, 입력 파일은 최대 128 MiB입니다. 초과 body는 부분 원문을 저장하지 않고 생략 사유를 표시합니다.
- 실제 body에 없는 필드나 예시값을 생성하지 않습니다. `bodyParams`는 필드명 정보입니다.
- HTML/Excel의 검토 후보는 규칙 기반의 분석 보조이며 취약점 확정이나 자동 검증 결과가 아닙니다.
- 원본 HAR/XML과 결과 DB/보고서는 `.gitignore`에서 제외합니다. Unix 출력 파일 권한은 기본 0600입니다. 이 자체는 디스크 암호화를 의미하지 않습니다.

## GitHub Actions

- `v81_ci.yml`: push/PR 시 단위 테스트·가상 보고서와 로컬 서버에 대한 Chromium 검증을 수행합니다. 실제 대상 스캔은 없습니다.
- `passive_recon.yml`: URL 발굴 + JS 구조 보존 + 인벤토리/보고서 통합. **수동 실행**만 가능합니다.
- `balanced`(기본): 크롤링·JS 다운로드·httpx·스크린샷을 선택적으로 실행합니다. 기본 선택은 모두 켜져 있으며 각 항목을 끌 수 있습니다.
- `passive`: Subfinder·Wayback·GAU 등 외부 제공자 조회만 수행하고 대상 프로빙·크롤링·JS 다운로드·스크린샷은 생략합니다.
- `offline`: 가상 데이터 가져오기와 보고서 검증만 수행하며 대상 Secrets가 필요하지 않습니다.
- 중복 실행은 대기시키고, 429/503·연속 오류·같은 호스트의 지속적인 지연 증가가 관찰되면 해당 수집기를 중단합니다. 자동 재시도·재개·스크린샷 재촬영은 없습니다.
- 보고서 생성 중 추가 대상 요청은 없습니다. 미수집 상태를 대상 장애로 단정하지 않습니다.
- 새 저장소에 `TARGET_DOMAINS`, `ACTIONS_CRYPTO_PASSWORD`를 별도로 등록해야 합니다. 원본 저장소의 Secrets는 자동 복사되지 않습니다.
- `GEMINI_API_KEY`는 사용하지 않습니다.
- Discord 전송은 기본 비활성입니다. 필요한 경우 저장소 변수 `ENABLE_DISCORD_DELIVERY=true`와 `DISCORD_WEBHOOK_URL`을 직접 설정합니다.
- 이전 실행 결과의 v8.1 DB를 복원할 수 있습니다. 새 보고서에서는 현재 scope에 맞는 기록만 표시합니다.
- 기존 파이프라인의 암호화된 결과물에는 `requests/`와 인벤토리 DB가 추가됩니다. 기존 ZIP 암호 형식은 이전 버전과 동일합니다.

## 검증

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

의존성 설치 외의 테스트·예제 import/report는 실제 대상에 요청을 보내지 않습니다. Playwright 라이브러리/브라우저와 Go 수집 도구는 별도 설치가 필요합니다.

## 소스 받기

```bash
git clone https://github.com/ohjun1998/passive-scan_v8.1_pub.git
cd passive-scan_v8.1_pub
```

기존 `passive-scan_v8_pub`을 수정용 remote로 지정하지 마세요.

참고 문서: [Burp Save items](https://portswigger.net/burp/documentation/desktop/tools/message-editor), [Playwright Request](https://playwright.dev/python/docs/api/class-request), [jsluice](https://github.com/BishopFox/jsluice).
