"""Offline recommendations with optional bounded, short Codex decisions."""
import html
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .ai_review import _publish, bounded_json, AGGREGATE_LIMIT
from .candidate_rules import KINDS, RULE_VERSION, recommend
from .candidate_review import PROMPT_VERSION, make_packet, execute_candidates
from .core import canonical, digest
from .review_batch import source


def select_for_ai(candidates, limit):
    """Give each present type a first slot before filling the remaining priority queue."""
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
    labels = {'rule_candidate': '규칙 후보', 'ai_retained': 'AI 후속 검토 추천',
              'ai_dismissed': 'AI 단서 기각', 'needs_context': '추가 맥락 필요'}
    sections = []
    for c in report['candidates']:
        rows = ''.join('<li><code>' + esc(r['observation_id'][:12]) + ' · ' + esc(r['location']) +
            ' ' + esc(r['pointer']) + ' [' + str(r['start']) + ':' + str(r['end']) + ']</code><pre>' +
            esc(r['excerpt']) + '</pre></li>' for r in c['evidence'])
        ai = c['ai'] or {}
        sections.append('<article data-kind="' + esc(c['kind']) + '" data-state="' + esc(c['state']) + '">' +
            '<h2>' + esc(KINDS[c['kind']]) + ' · ' + esc(c['priority']) + '</h2><p><b>' +
            esc(c['method']) + '</b> ' + esc(c['url']) + '</p><p>' + esc(labels[c['state']]) +
            ' · 단서 강도 ' + esc(c['signal_strength']) + '</p><p>' + esc(c['reason']) + '</p>' +
            ('<p><b>AI 판단:</b> ' + esc(ai['reason']) + '</p>' if ai else '') +
            '<p><b>다음 확인:</b> ' + esc(ai.get('next_check', c['next_check'])) + '</p>' +
            '<p>판단 대상: <code>' + esc(', '.join(c['subject_ids'])) + '</code></p>' +
            '<p>비교 자료: <code>' + esc(', '.join(c['support_ids']) or '없음') + '</code></p><ul>' + rows +
            '</ul><p class="note">' + esc(' '.join(c['limitations'])) + '</p></article>')
    options = ''.join('<option value="' + esc(k) + '">' + esc(v) + '</option>' for k, v in KINDS.items())
    states = ''.join('<option value="' + esc(k) + '">' + esc(v) + '</option>' for k, v in labels.items())
    summary = report['summary']
    return ('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
        'script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
        '<title>저장 증거 진단 후보</title><style>body{font:15px/1.7 system-ui,sans-serif;max-width:1100px;margin:30px auto;padding:18px;color:#243746;background:#f5f7fa}'
        'article{background:white;border:1px solid #d6dfe8;border-left:5px solid #327cad;border-radius:8px;padding:18px;margin:18px 0}'
        'h1{font-size:26px}h2{font-size:20px}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}pre{background:#f0f3f6;padding:10px}'
        '.note{background:#fff3dc;padding:12px}select,input{font:inherit;padding:8px;margin:4px}li{margin:8px 0}</style>'
        '<h1>저장 요청·응답 진단 후보</h1><p class="note">후보와 검토 순서를 추천합니다. 취약점 확정·재현·안전 판정은 수행하지 않았습니다. '
        'AI에 전달하지 않은 기록도 있으며 규칙 비탐지는 취약점 부재를 의미하지 않습니다.</p><p>' +
        esc('규칙 처리 ' + str(summary['rule_processed_records']) + '건 · 후보 ' + str(summary['candidates']) +
            '개 · AI 검토 ' + str(summary['ai_reviewed_candidates']) + '/' + str(summary['ai_selected_candidates']) +
            '개 · 모델 호출 ' + str(summary['model_calls']) + '회 · 대상 추가 요청 0건') + '</p>' +
        '<label>유형 <select id="kind"><option value="">전체</option>' + options + '</select></label>' +
        '<label>상태 <select id="state"><option value="">전체</option>' + states + '</select></label>' +
        '<input id="search" aria-label="후보 검색" placeholder="URL·근거·다음 확인 검색"><p id="count"></p>' +
        ''.join(sections) + ('<p>현재 저장 증거에서 지원 규칙에 해당하는 단서를 찾지 못했습니다.</p>' if not sections else '') +
        '<script>const kind=document.getElementById("kind"),state=document.getElementById("state"),search=document.getElementById("search");'
        'function filter(){let n=0;for(const a of document.querySelectorAll("article")){const show=(!kind.value||a.dataset.kind===kind.value)&&'
        '(!state.value||a.dataset.state===state.value)&&a.textContent.toLowerCase().includes(search.value.toLowerCase());a.hidden=!show;n+=show?1:0;}'
        'document.getElementById("count").textContent=n+"개 표시";}for(const x of [kind,state,search])x.addEventListener("input",filter);filter();</script></html>')


def create_recommendations(report_path, output, patterns, authority=None, ai=False, ai_limit=24,
                           batch_size=8, workers=2, timeout=300, model=None, first_response_timeout=180):
    from .codex_review import ReviewFailure, _execution_settings, configuration_session
    started = time.monotonic()
    if not 1 <= ai_limit <= 100 or not 1 <= batch_size <= 12 or not 1 <= workers <= 4:
        raise ValueError('Invalid candidate AI budget')
    _execution_settings(timeout, model, first_response_timeout)
    output = Path(output)
    if output.exists() or output.is_symlink(): raise ValueError('Use a new recommendation output directory')
    records, receipts, manifest = source(report_path)
    candidates, clean, outside = recommend(records, patterns, authority)
    selected = select_for_ai(candidates, ai_limit) if ai else []
    # Pack only bounded evidence excerpts. Large candidate contexts are explicitly
    # left for manual review, never silently truncated or sent over the budget.
    packets = []; current = []; oversized = []
    for c in selected:
        if len(canonical(make_packet([c])).encode()) > 24576:
            oversized.append(c['candidate_id']); continue
        proposed = current + [c]
        if current and (len(proposed) > batch_size or len(canonical(make_packet(proposed)).encode()) > 24576):
            packets.append(make_packet(current)); current = []
        current.append(c)
    if current: packets.append(make_packet(current))
    by_id = {c['candidate_id']: c for c in candidates}; executions = []; model_started = time.monotonic()
    def run(packet):
        with configuration_session():
            return execute_candidates(packet, timeout, model, first_response_timeout)
    if packets:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {executor.submit(run, p): p for p in packets}
            for future in as_completed(pending):
                packet = pending[future]
                try:
                    decisions, receipt = future.result()
                    # Revalidate even an injected/test adapter before publishing.
                    from .candidate_review import validate_decisions
                    decisions = validate_decisions(decisions, packet)
                    if (receipt.get('status') != 'completed' or receipt.get('provider') != 'codex_chatgpt_login' or
                        receipt.get('model_execution_verified') is not True or
                        receipt.get('completion_events_verified') is not True or receipt.get('candidate_validation') != 'verified'):
                        raise ValueError('Unverified candidate model execution')
                    for decision in decisions['reviews']:
                        c = by_id[decision['candidate_id']]
                        c['ai'] = dict(decision, packet_id=packet['packet_id'])
                        c['state'] = {'retain': 'ai_retained', 'dismiss': 'ai_dismissed', 'needs_context': 'needs_context'}[decision['disposition']]
                        c['priority'] = decision['priority']
                    executions.append(dict(receipt, packet_id=packet['packet_id'], candidate_ids=[c['candidate_id'] for c in packet['candidates']]))
                except (ReviewFailure, ValueError, KeyError, TypeError, OSError) as error:
                    executions.append({'packet_id': packet['packet_id'], 'candidate_ids': [c['candidate_id'] for c in packet['candidates']],
                        'status': 'failed', 'code': error.code if isinstance(error, ReviewFailure) else 'INVALID_CANDIDATE_RESULT',
                        'stage': error.stage if isinstance(error, ReviewFailure) else 'candidate_validation',
                        'model_execution_verified': False, 'target_requests_sent': 0})
    executions.sort(key=lambda e: e['packet_id'])
    candidates.sort(key=lambda c: (c['state'] == 'ai_dismissed', {'high': 0, 'medium': 1, 'low': 2}[c['priority']], c['kind'], c['candidate_id']))
    subject_candidates = {}
    for c in candidates:
        for oid in c['subject_ids']: subject_candidates.setdefault(oid, []).append(c)
    record_rows = []
    for oid, r in clean.items():
        record_rows.append({'observation_id': oid, 'method': r['method'], 'url': r['url'],
            'observed': r.get('observed', False), 'rule_processed': True,
            'request_body_complete': bool((r.get('body') or {}).get('complete')),
            'response_body_complete': bool(((r.get('response') or {}).get('body') or {}).get('complete')),
            'candidate_ids': [c['candidate_id'] for c in subject_candidates.get(oid, [])],
            'ai_subject_reviewed': any(c['ai'] for c in subject_candidates.get(oid, []))})
    summary = {'source_records': len(records), 'out_of_scope_records': outside, 'rule_processed_records': len(clean),
        'candidates': len(candidates), 'by_kind': dict(Counter(c['kind'] for c in candidates)),
        'ai_selected_candidates': len(selected), 'ai_reviewed_candidates': sum(bool(c['ai']) for c in candidates),
        'ai_reviewed_by_kind': dict(Counter(c['kind'] for c in candidates if c['ai'])),
        'ai_not_reviewed_candidates': sum(not c['ai'] for c in candidates),
        'ai_failed_packets': sum(e['status'] == 'failed' for e in executions), 'ai_oversized_candidates': len(oversized),
        'model_calls': len(packets), 'elapsed_seconds': round(time.monotonic() - started, 3),
        'model_phase_seconds': round(time.monotonic() - model_started, 3),
        'target_requests_sent': 0, 'confirmed_vulnerabilities': 0, 'reproduction_verified': 0}
    result = {'schema_version': '8.7', 'rule_version': RULE_VERSION, 'prompt_version': PROMPT_VERSION,
        'source_receipts': receipts, 'source_manifest_verified': manifest is not None, 'scope': patterns,
        'authority_configuration_sha256': digest(authority) if authority is not None else None,
        'ai_settings': {'requested': ai, 'max_candidates': ai_limit, 'batch_size': batch_size, 'workers': workers,
                        'requested_model': model, 'first_response_timeout': min(timeout, first_response_timeout), 'timeout': timeout},
        'summary': summary, 'records': record_rows, 'candidates': candidates, 'executions': executions,
        'oversized_candidate_ids': oversized,
        'notice': 'Leads and review priorities only. Rule processing and excerpt checks do not prove vulnerabilities. AI selection is bounded; unselected and failed leads remain visible. No target requests or key validation.'}
    files = {'recommendations.json': bounded_json(result, AGGREGATE_LIMIT), 'index.html': render(result)}
    if len(files['index.html'].encode()) > AGGREGATE_LIMIT: raise ValueError('Candidate HTML size limit exceeded')
    for packet in packets:
        files['model-inputs/' + packet['packet_id'] + '.json'] = bounded_json(packet)
    _publish(output, files)
    return result
