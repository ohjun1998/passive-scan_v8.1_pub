# GitHub 작업 과정

`main`은 기본 코드입니다. GitHub 첫 화면·일반적인 clone·기본 ZIP 다운로드는 main 기준입니다.

**브랜치(branch)**는 main과 분리해 변경을 만드는 작업 갈래입니다. 브랜치에 업로드했다고 main까지 바뀐 것은 아닙니다. **커밋(commit)**은 그 갈래에서 변경 내용을 저장한 기록입니다.

**PR(Pull Request)**은 브랜치의 변경을 main에 합쳐 달라는 검토 요청입니다. 변경 파일·설명·자동 테스트 결과를 한 화면에서 확인할 수 있습니다. **Draft PR**은 아직 작업 중인 초안 상태이며, 검토 준비가 끝나면 Ready로 전환합니다. **병합(merge)**이 완료되어야 변경이 main에 들어갑니다.

```mermaid
flowchart TB
    A["main · 현재 기본 코드"] --> B["branch · 변경 작업"]
    B --> C["commit + push · GitHub에 기록·업로드"]
    C --> D["Draft PR · 작업 중인 변경 확인"]
    D --> E{"코드 검토·자동 테스트"}
    E -->|수정 필요| F["브랜치 수정·추가 커밋"]
    F --> G["테스트 재검증"]
    E -->|통과| H["Ready PR · 병합 준비"]
    G --> H
    H --> I["merge · main에 변경 합치기"]
    I --> J["git pull 또는 새 ZIP · 최신 코드 사용"]
```

v8.4.1은 PR #1, v8.5.0은 PR #2로 main에 병합했습니다. v8.5.1은 `codex/v851-runtime-diagnostics` 브랜치의 PR #3에서 CI를 통과하고 main에 병합했습니다. main의 버전·릴리스 안내 변경 시 배포 작업이 소스와 실제 Chromium을 검증하고, 검증한 커밋에 태그·ZIP·SHA256SUMS를 연결해 한계를 명시한 사전 배포를 만듭니다. 기존 릴리스는 덮어쓰지 않습니다.

사용자 요청에 따라 GitHub 변경과 관련된 대화는 `docs/chat-logs/날짜/`에 사용자 요청 원문과 응답·작업 요약으로 함께 보관합니다.

GitHub에 올라간 코드와 컴퓨터에서 실행하는 코드는 별개입니다. 기존 로컬 설치는 main을 pull하거나 새 ZIP을 받아야 업데이트됩니다. GitHub에 병합해도 이미 실행 중인 프로그램이 자동 교체되지는 않습니다.
