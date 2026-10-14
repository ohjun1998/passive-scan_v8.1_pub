# 정보 노출 AI 검토 프롬프트 적용 패키지

API 응답 민감정보 과다 노출, 수집된 JS/HTML 비밀정보 노출, 오류 메시지 내부정보 노출을 검토하도록 기존 v8.4 `make_prompt()`에 판단 기준을 추가했습니다.

## 현재 적용 상태

이 패키지는 적용용 수정본입니다. 환경 정리로 최신 v8.4 로컬 개발본이 없어졌으며, GitHub main은 8.2.0이고 AI 검토 파일이 없습니다. 따라서 최신 전체 프로젝트와 GitHub에는 아직 적용되지 않았습니다. 완성된 v8.4 프로그램 전체를 포함한 소스 ZIP이 아닙니다.

이전에 확인한 `make_prompt()` 함수의 구조를 기준으로 패치 적용, JSON 보존, 구문, 원본 불일치 거부, 중복 적용 방지 검사를 수행했습니다. 실제 모델 호출이나 전체 프로그램 회귀 테스트는 수행하지 않았습니다.

## 파일

- `disclosure_prompt_update.patch`: 기존 v8.4 함수에 적용할 코드 변경. 문서 반영은 아래 적용 도구를 사용하거나 수동으로 진행합니다.
- `make_prompt_replacement.py`: 수정된 함수와 JSON 직렬화 예시. **전체 codex_review.py를 이 파일로 교체하지 마세요.**
- `updated_fixed_prompt.txt`: 데이터 JSON을 제외한 최종 고정 지시문 전체.
- `disclosure_rules.txt`: 이번에 추가한 네 개 지시 블록.
- `apply_prompt_update.py`: 이전 함수 일치 검사를 통과하면 백업 후 코드와 문서 링크 적용.
- `docs/PROMPT_DISCLOSURE_REVIEW.md`: 판단 기준, 시간 순서 전체 흐름, 유스케이스.
- `verification`: 로컬 검증 코드·결과·이전에 확인한 함수의 비교용 복사본.

## 적용

최신 v8.4 소스가 있는 경로에서 먼저 검사합니다.

```bash
python apply_prompt_update.py --project /path/to/passive-scan
```

검사를 통과하면 적용합니다.

```bash
python apply_prompt_update.py --project /path/to/passive-scan --apply
```

함수가 이전 원본과 다르면 적용을 거부합니다. 그 경우 최신 소스를 기준으로 병합해야 합니다. 이미 적용된 함수에는 중복 지시문을 넣지 않습니다. 원본 파일은 `.before_disclosure_prompt` 이름으로 백업합니다.

## 범위

프롬프트만 개선합니다. 신규 JS 다운로드, 요청 재전송, 비밀키 유효성 검사, 입력 마스킹·본문 한도·출력 JSON schema 변경은 포함하지 않습니다. 수집하지 않았거나 마스킹된 내용은 AI가 확인할 수 없습니다. 판단 결과는 기존 의심·정상 가능성·증거 부족 분류와 보고서 초안 필드에 담습니다.

수동 ChatGPT 검토에는 새 prompt.txt와 기존 schema.json을 함께 제공해야 합니다. 기존 prepare 기능은 이 함수 수정 후 새 출력 디렉터리에서 실행해야 새로운 지시문이 반영됩니다. 이미 생성된 prompt.txt는 자동으로 바뀌지 않습니다.
