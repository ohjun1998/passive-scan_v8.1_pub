"""Offline recommendations with optional bounded, short Codex decisions."""
import html
import time
from collections import Counter
from pathlib import Path

from .ai_review import _publish, bounded_json, AGGREGATE_LIMIT
from .candidate_rules import KINDS, RULE_VERSION, recommend
from .candidate_catalog import CATALOG, CATALOG_VERSION, CATALOG_CHECKED_AT, CATALOG_SOURCE
from .candidate_review import PROMPT_VERSION, execute_candidates
from .candidate_discovery import execute_discovery
from .candidate_context import EvidenceContext, display_record
from .candidate_feedback import read_feedback
from .candidate_intelligence import execute as run_intelligence
from .core import canonical, digest, MASK, get_header
from .review_batch import source


def select_for_ai(candidates, limit, include_surfaces=False):
    """Give each present type a first slot before filling the remaining priority queue."""
    candidates = [c for c in candidates if include_surfaces or c.get('lead_class', 'evidence_signal') == 'evidence_signal']
    selected = []; seen = set(); kinds = set()
    for c in candidates:
        if c['kind'] not in kinds and len(selected) < limit:
            kinds.add(c['kind']); selected.append(c); seen.add(c['candidate_id'])
    for c in candidates:
        if len(selected) >= limit: break
        if c['candidate_id'] not in seen: selected.append(c); seen.add(c['candidate_id'])
    return selected


def render(report):
    def esc(value): return html.escape(str(value), quote=True)
    labels = {'rule_candidate': '규칙 후보', 'discovery_hypothesis': 'AI 탐색 가설·미확정', 'ai_retained': 'AI 후속 검토 추천',
              'ai_dismissed': 'AI 단서 기각', 'needs_context': '추가 맥락 필요'}
    sections = []
    for c in report['candidates']:
        rows = ''.join('<li><code>' + esc(r['observation_id'][:12]) + ' · ' + esc(r['location']) +
            ' ' + esc(r['pointer']) + ' [' + str(r['start']) + ':' + str(r['end']) + ']</code><pre>' +
            esc(r['excerpt']) + '</pre></li>' for r in c['evidence'])
        ai = c['ai'] or {}
        human = c.get('human_review') or {}
        human_labels = {'follow_up': '후속 점검 채택', 'dismiss': '단서 기각', 'needs_context': '추가 맥락 필요'}
        bundle = c.get('evidence_bundle') or {}
        related = ''.join('<li><a href="evidence-records/' + esc(r['observation_id']) + '.json">' +
            esc(r['method'] + ' ' + r['url']) + '</a> · 상태 ' + esc(r.get('response_status')) + ' · 계정 ' +
            esc((r.get('context') or {}).get('actor', '미지정')) + '</li>' for r in bundle.get('records', []))
        context_refs = ''.join('<li><code>' + esc(r['observation_id'][:12] + ' · ' + r['location'] + ' ' + r['pointer']) +
            '</code><pre>' + esc(r['excerpt']) + '</pre></li>' for r in bundle.get('evidence', []))
        context_view = ('<details><summary>관련 저장 증거·응답 차이 보기</summary><p>마스킹된 저장 기록의 표시용 사본입니다. 큰 본문은 표시 제한이 있으며 누락 표시를 확인하세요.</p><ul>' + related +
            '</ul><pre>' + esc(canonical({'relations': bundle.get('relations', []), 'response_differences': bundle.get('response_differences', []),
                'omitted_related_records': bundle.get('omitted_related_records', 0)})) + '</pre><ul>' + context_refs + '</ul></details>') if bundle else ''
        sections.append('<article data-human="' + esc(human.get('decision', 'unreviewed')) + '" data-kind="' + esc(c['kind']) + '" data-class="' + esc(c['lead_class']) + '" data-state="' + esc(c['state']) + '">' +
            '<h2>' + ('AI 탐색 가설' if c.get('origin') == 'llm_discovery' else '단서 후보' if c['lead_class'] == 'evidence_signal' else '기능 점검 대상') + ' · ' + esc(KINDS[c['kind']]) + ' · ' + esc(c['priority']) + '</h2><p><b>' +
            esc(c['method']) + '</b> ' + esc(c['url']) + '</p><p>' + esc(labels[c['state']]) +
            ' · 단서 강도 ' + esc(c['signal_strength']) + '</p><p>' + esc(c['reason']) + '</p>' +
            ('<p><b>AI 판단' + (' · 과거 결과 재사용' if ai.get('reused') else '') + ':</b> ' + esc(ai['reason']) + '</p>' if ai else '') +
            ('<p class="note"><b>사람 판정:</b> ' + esc(human_labels[human['decision']]) + ' · ' + esc(human['note']) + '</p>' if human else '') +
            '<p><b>다음 확인:</b> ' + esc(ai.get('next_check', c['next_check'])) + '</p>' +
            '<p>판단 대상: <code>' + esc(', '.join(c['subject_ids'])) + '</code></p>' +
            '<p>비교 자료: <code>' + esc(', '.join(c['support_ids']) or '없음') + '</code></p><ul>' + rows +
            '</ul>' + context_view + '<p>후보 ID: <code>' + esc(c['candidate_id']) + '</code></p><p class="note">' + esc(' '.join(c['limitations'])) + '</p></article>')
    options = ''.join('<option value="' + esc(k) + '">' + esc(v) + '</option>' for k, v in KINDS.items())
    states = ''.join('<option value="' + esc(k) + '">' + esc(v) + '</option>' for k, v in labels.items())
    summary = report['summary']
    coverage_labels = {'matched_signal': '단서 있음', 'surface_only': '기능 발견·결함 미판정',
                       'no_matching_saved_signal': '일치 단서 없음·안전 판정 아님', 'additional_capture_required': '추가 수집 필요·미평가'}
    coverage = ''.join('<tr><td>' + esc(KINDS[c['kind']]) + '</td><td>' + esc(coverage_labels[c['status']]) +
        '</td><td>' + str(c['signal_candidates']) + '/' + str(c['review_surfaces']) + '</td><td>' +
        esc(c['required_followup']) + '</td></tr>' for c in report['type_coverage'])
    return ('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
        'script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
        '<title>저장 증거 진단 후보</title><style>body{font:15px/1.7 system-ui,sans-serif;max-width:1100px;margin:30px auto;padding:18px;color:#243746;background:#f5f7fa}'
        'article{background:white;border:1px solid #d6dfe8;border-left:5px solid #327cad;border-radius:8px;padding:18px;margin:18px 0}'
        'h1{font-size:26px}h2{font-size:20px}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}pre{background:#f0f3f6;padding:10px}'
        '.note{background:#fff3dc;padding:12px}select,input{font:inherit;padding:8px;margin:4px}li{margin:8px 0}td,th{padding:8px;text-align:left;border-bottom:1px solid #d6dfe8}table{width:100%;border-collapse:collapse}</style>'
        '<h1>저장 요청·응답 진단 후보</h1><p class="note">후보와 검토 순서를 추천합니다. 취약점 확정·재현·안전 판정은 수행하지 않았습니다. '
        'AI에 전달하지 않은 기록도 있으며 규칙 비탐지는 취약점 부재를 의미하지 않습니다.</p><p>' +
        esc('규칙 처리 ' + str(summary['rule_processed_records']) + '건 · 단서 후보 ' + str(summary['signal_candidates']) +
            '개 · 기능 점검 대상 ' + str(summary['review_surfaces']) +
            '개 · AI 검토 ' + str(summary['ai_reviewed_candidates']) + '/' + str(summary['ai_selected_candidates']) +
            '개 · 재사용 ' + str(summary.get('ai_reused_candidates', 0)) + '개 · 탐색 가설 ' + str(summary.get('discovery_hypotheses', 0)) +
            '개 · 탐색 검토 새 ' + str(summary.get('discovery_new_tasks', 0)) + '/재사용 ' + str(summary.get('discovery_reused_tasks', 0)) +
            '묶음 · 이번 모델 호출 ' + str(summary['model_calls']) + '회 · 대상 추가 요청 0건') + '</p>' +
        '<p>규칙 밖 탐색의 빈 결과도 안전 판정은 아닙니다. 탐색·미선택·실패·재사용 상태와 사람 판정은 JSON 보고서에 따로 보존합니다.</p>' +
        '<details><summary>유형별 점검 범위·부족한 자료</summary><p>공식 Academy 30개 취약점 관련 주제 매핑입니다. Burp Scanner의 모든 개별 검사·자동 탐지를 구현한 범위가 아닙니다.</p><table><tr><th>유형</th><th>상태</th><th>단서/점검 대상</th><th>추가 확인</th></tr>' + coverage + '</table></details>' +
        '<label>구분 <select id="leadclass"><option value="">전체</option><option value="evidence_signal" selected>단서 후보</option><option value="review_surface">기능 점검 대상</option></select></label>' +
        '<label>유형 <select id="kind"><option value="">전체</option>' + options + '</select></label>' +
        '<label>상태 <select id="state"><option value="">전체</option>' + states + '</select></label>' +
        '<label>사람 판정 <select id="human"><option value="">전체</option><option value="unreviewed">미검토</option><option value="follow_up">후속 점검 채택</option><option value="dismiss">단서 기각</option><option value="needs_context">추가 맥락 필요</option></select></label>' +
        '<input id="search" aria-label="후보 검색" placeholder="URL·근거·다음 확인 검색"><p id="count"></p>' +
        ''.join(sections) + ('<p>현재 저장 증거에서 지원 규칙에 해당하는 단서를 찾지 못했습니다.</p>' if not sections else '') +
        '<script>const kind=document.getElementById("kind"),state=document.getElementById("state"),leadclass=document.getElementById("leadclass"),human=document.getElementById("human"),search=document.getElementById("search");'
        'function filter(){let n=0;for(const a of document.querySelectorAll("article")){const show=(!kind.value||a.dataset.kind===kind.value)&&'
        '(!state.value||a.dataset.state===state.value)&&(!leadclass.value||a.dataset.class===leadclass.value)&&(!human.value||a.dataset.human===human.value)&&a.textContent.toLowerCase().includes(search.value.toLowerCase());a.hidden=!show;n+=show?1:0;}'
        'document.getElementById("count").textContent=n+"개 표시";}for(const x of [kind,state,leadclass,human,search])x.addEventListener("input",filter);filter();</script></html>')


def create_recommendations(report_path, output, patterns, authority=None, ai=False, ai_limit=24,
                           batch_size=8, workers=2, timeout=300, model=None, first_response_timeout=180, include_surfaces=False,
                           discover=False, discovery_limit=4, cache_path=None, cache_age=86400, feedback_path=None):
    from .codex_review import _execution_settings, DEFAULT_MODEL, DEFAULT_REASONING_EFFORT
    model = DEFAULT_MODEL if model is None else model
    started = time.monotonic()
    if not 1 <= ai_limit <= 100 or not 1 <= batch_size <= 12 or not 1 <= workers <= 4:
        raise ValueError('Invalid candidate AI budget')
    if discover and (not ai or not 1 <= discovery_limit <= min(ai_limit, 24)):
        raise ValueError('Discovery needs --ai and a bounded share of its unit budget')
    _execution_settings(timeout, model, first_response_timeout)
    output = Path(output)
    if output.exists() or output.is_symlink(): raise ValueError('Use a new recommendation output directory')
    if cache_path is not None:
        cp = Path(cache_path).resolve()
        if cp.is_relative_to(Path(report_path).resolve()) or cp.is_relative_to(output.resolve()):
            raise ValueError('AI cache must be outside immutable source and output reports')
    records, receipts, manifest, analysis = source(report_path, include_analysis=True)
    candidates, clean, outside = recommend(records, patterns, authority)
    context = EvidenceContext(clean, analysis)
    context.attach(candidates)
    human_feedback = read_feedback(feedback_path)
    model_started = time.monotonic()
    run = run_intelligence(candidates, context, ai=ai, ai_limit=ai_limit, batch_size=batch_size, workers=workers,
        timeout=timeout, model=model, first_response_timeout=first_response_timeout, include_surfaces=include_surfaces,
        discover=discover, discovery_limit=discovery_limit, cache_path=cache_path, cache_age=cache_age,
        feedback=human_feedback, scope=patterns, candidate_adapter=execute_candidates, discovery_adapter=execute_discovery)
    candidates = run['candidates']
    if len(candidates) > 5600: raise ValueError('Recommendation output candidate budget exceeded')
    subject_candidates = {}
    for c in candidates:
        for oid in c['subject_ids']: subject_candidates.setdefault(oid, []).append(c)
    discovery_states = {oid: row['status'] for row in run['discovery_tasks'] for oid in row['subject_ids']}
    record_rows = []
    for oid, r in clean.items():
        record_rows.append({'observation_id': oid, 'method': r['method'], 'url': r['url'],
            'observed': r.get('observed', False), 'rule_processed': True,
            'request_body_complete': bool((r.get('body') or {}).get('complete')),
            'response_body_complete': bool(((r.get('response') or {}).get('body') or {}).get('complete')),
            'candidate_ids': [c['candidate_id'] for c in subject_candidates.get(oid, [])],
            'ai_subject_reviewed': any(c['ai'] for c in subject_candidates.get(oid, [])),
            'discovery_status': discovery_states.get(oid, 'not_selected')})
    summary = {'source_records': len(records), 'out_of_scope_records': outside, 'rule_processed_records': len(clean),
        'candidates': len(candidates), 'by_kind': dict(Counter(c['kind'] for c in candidates)),
        'signal_candidates': sum(c['lead_class'] == 'evidence_signal' for c in candidates),
        'review_surfaces': sum(c['lead_class'] == 'review_surface' for c in candidates),
        **run['summary'], 'elapsed_seconds': round(time.monotonic() - started, 3),
        'model_phase_seconds': round(time.monotonic() - model_started, 3),
        'target_requests_sent': 0, 'target_dns_lookups': 0, 'confirmed_vulnerabilities': 0, 'reproduction_verified': 0}
    type_coverage = []
    masked_cors = any(get_header((r.get('response') or {}).get('headers', []), 'access-control-allow-credentials') == MASK for r in clean.values())
    for key, entry in CATALOG.items():
        matches = [c for c in candidates if c['kind'] == key]
        signals = sum(c['lead_class'] == 'evidence_signal' for c in matches)
        surfaces = len(matches) - signals
        status = ('additional_capture_required' if entry['assessment_mode'] == 'additional_capture_required' else
                  'matched_signal' if signals else 'surface_only' if surfaces else 'no_matching_saved_signal')
        limitation = 'Legacy ACAC value was masked; do not infer its boolean value.' if key == 'cors' and masked_cors else None
        if limitation and not signals: status = 'additional_capture_required'
        type_coverage.append(dict(entry, status=status, signal_candidates=signals, review_surfaces=surfaces, capture_limitation=limitation))
    result = {'schema_version': '8.9', 'rule_version': RULE_VERSION, 'prompt_version': PROMPT_VERSION,
        'catalog_version': CATALOG_VERSION, 'catalog_checked_at': CATALOG_CHECKED_AT, 'catalog_source': CATALOG_SOURCE,
        'type_coverage': type_coverage, 'feedback_summary': run['feedback_summary'],
        'discovery_tasks': run['discovery_tasks'], 'discovery_coverage': run['discovery_coverage'],
        'capture_constraints': ['Normalized records omit raw HTTP framing; request smuggling is not assessed.',
            'Tokens/cookies are masked; JWT contents/signatures and cookie attributes cannot be reconstructed.',
            'Multipart file bytes and WebSocket frames are not retained by this HTTP report.',
            'Saved observations do not establish concurrency, parser differences or cache-key reuse.'],
        'source_receipts': receipts, 'source_manifest_verified': manifest is not None, 'scope': patterns,
        'authority_configuration_sha256': digest(authority) if authority is not None else None,
        'ai_settings': {'requested': ai, 'max_new_units': ai_limit, 'max_candidates': ai_limit, 'batch_size': batch_size, 'workers': workers,
                        'requested_model': model, 'requested_reasoning_effort': DEFAULT_REASONING_EFFORT,
                        'include_surfaces': include_surfaces, 'discovery_requested': discover,
                        'max_new_discovery_tasks': discovery_limit, 'cache_requested': cache_path is not None, 'cache_max_age': cache_age,
                        'first_response_timeout': min(timeout, first_response_timeout), 'timeout': timeout},
        'summary': summary, 'records': record_rows, 'candidates': candidates, 'executions': run['executions'],
        'oversized_candidate_ids': run['oversized'],
        'notice': 'Saved-only leads and hypotheses, not verified vulnerabilities. Cached model results are historical, not fresh calls. Human decisions apply only to matching saved evidence. Discovery is bounded and a negative result is not a safety verdict. No target requests, DNS or key validation.'}
    display_ids = {r['observation_id'] for c in candidates for r in c['evidence_bundle']['records']}
    if len(display_ids) > 1000: raise ValueError('Evidence display budget exceeded; narrow source scope')
    views = {'evidence-records/' + oid + '.json': bounded_json(display_record(clean[oid]), 256 * 1024) for oid in display_ids}
    if sum(len(value.encode()) for value in views.values()) > 32 * 1024 * 1024: raise ValueError('Evidence display byte budget exceeded')
    result['evidence_display'] = {'records': len(views), 'body_preview_bytes': 16384, 'display_only': True}
    files = {'recommendations.json': bounded_json(result, AGGREGATE_LIMIT), 'index.html': render(result), **views}
    if len(files['index.html'].encode()) > AGGREGATE_LIMIT: raise ValueError('Candidate HTML size limit exceeded')
    for mode, packet in run['inputs']:
        files['model-inputs/' + packet['packet_id'] + '.json'] = bounded_json(packet)
    for packet_id, value in run['outputs'].items():
        files['model-results/' + packet_id + '.json'] = bounded_json(value)
    _publish(output, files)
    return result
