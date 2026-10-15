"""One bounded model budget shared by candidate review and saved-only discovery."""
import copy
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from .core import canonical, digest
from .candidate_cache import DecisionCache, runtime_fingerprint, verified_receipt
from .candidate_review import make_packet, validate_decisions, execute_candidates, PROMPT_VERSION, prompt_for as review_prompt
from .candidate_discovery import build_tasks, validate as validate_discovery, execute_discovery, hypotheses, DISCOVERY_VERSION, prompt_for as discovery_prompt
from .candidate_feedback import apply_feedback


def order(c):
    human = (c.get('human_review') or {}).get('decision')
    return (human == 'dismiss', c['lead_class'] == 'review_surface', human != 'follow_up',
            c['state'] == 'ai_dismissed', {'high': 0, 'medium': 1, 'low': 2}[c['priority']], c['kind'], c['candidate_id'])


def choose(candidates, limit):
    selected = []; seen = set(); kinds = set()
    for c in sorted(candidates, key=order):
        if c['kind'] not in kinds and len(selected) < limit:
            selected.append(c); seen.add(c['candidate_id']); kinds.add(c['kind'])
    for c in sorted(candidates, key=order):
        if len(selected) >= limit: break
        if c['candidate_id'] not in seen: selected.append(c); seen.add(c['candidate_id'])
    return selected


def pack(candidates, batch_size):
    packets = []; current = []; oversized = []
    for c in candidates:
        if len(canonical(make_packet([c])).encode()) > 24576: oversized.append(c['candidate_id']); continue
        proposed = current + [c]
        if current and (len(proposed) > batch_size or len(canonical(make_packet(proposed)).encode()) > 24576):
            packets.append(make_packet(current)); current = []
        current.append(c)
    if current: packets.append(make_packet(current))
    return packets, oversized


def execute(candidates, context, *, ai, ai_limit, batch_size, workers, timeout, model, first_response_timeout,
            include_surfaces, discover, discovery_limit, cache_path, cache_age, feedback, scope, candidate_adapter=None, discovery_adapter=None):
    from .codex_review import configuration_session, ReviewFailure
    apply_feedback(candidates, feedback)
    eligible = [c for c in candidates if (include_surfaces or c['lead_class'] == 'evidence_signal') and
                (c.get('human_review') or {}).get('decision') != 'dismiss']
    cache = DecisionCache(cache_path if ai else None, runtime_fingerprint(model) if ai and cache_path is not None else None, cache_age)
    executions = []; inputs = []; outputs = {}; task_rows = []; discovered = []; reuse_count = 0
    new_rules = []; reused_rules = []; fresh_discovery = []; task_summary = {'eligible_records': 0, 'representative_tasks': 0}
    scope_key = sorted(scope)
    template_sha = digest(review_prompt(make_packet([])))
    def unit(c): return {'scope': scope_key, 'prompt_version': PROMPT_VERSION, 'prompt_template_sha256': template_sha, 'candidate': make_packet([c])['candidates'][0]}
    def discovery_unit(task): return {'scope': scope_key, 'task': task, 'version': DISCOVERY_VERSION, 'prompt_sha256': digest(discovery_prompt(task))}
    def review_validator(c):
        expected = make_packet([c])['candidates'][0]
        def check(packet, result, receipt):
            claimed = dict(packet); claimed_id = claimed.pop('packet_id')
            if digest(claimed) != claimed_id or packet.get('prompt_version') != PROMPT_VERSION:
                raise ValueError('Cached input changed')
            if not verified_receipt(receipt, 'candidate_validation') or receipt.get('prompt_sha256') != digest(review_prompt(packet)):
                raise ValueError('Unverified cached review prompt')
            match = next((x for x in packet['candidates'] if x['candidate_id'] == c['candidate_id']), None)
            if match != expected: raise ValueError('Cached candidate context mismatch')
            value = validate_decisions(result, packet)
            return next(x for x in value['reviews'] if x['candidate_id'] == c['candidate_id'])
        return check
    def apply(c, decision, packet_id, reused=False):
        c['ai'] = dict(decision, packet_id=packet_id, reused=reused)
        c['state'] = {'retain': 'ai_retained', 'dismiss': 'ai_dismissed', 'needs_context': 'needs_context'}[decision['disposition']]
        c['priority'] = decision['priority']
    def reused_execution(mode, packet_id, ids, provenance):
        executions.append({'mode': mode, 'packet_id': packet_id, 'candidate_ids': ids, 'status': 'reused',
            'fresh_model_execution': False, 'cached_model_result_verified': True, 'target_requests_sent': 0, **provenance})
    try:
        if ai:
            for c in eligible:
                cached = cache.get('candidate', unit(c), review_validator(c))
                if cached:
                    decision, provenance = cached
                    apply(c, decision, provenance['origin_packet_id'], True); reused_rules.append(c)
                    reused_execution('candidate', provenance['origin_packet_id'], [c['candidate_id']], provenance)
                else: new_rules.append(c)
        if ai and discover:
            tasks, task_summary = build_tasks(context, candidates)
            for task in tasks:
                def checked(packet, result, receipt, expected=task):
                    if packet != expected or not verified_receipt(receipt, 'discovery_validation') or receipt.get('prompt_sha256') != digest(discovery_prompt(packet)):
                        raise ValueError('Unverified cached discovery')
                    return validate_discovery(result, packet)
                cached = cache.get('discovery', discovery_unit(task), checked)
                if cached:
                    result, provenance = cached
                    added = hypotheses(result, task, context)
                    for c in added: c['ai']['reused'] = True
                    discovered += added; reuse_count += 1
                    task_rows.append({'packet_id': task['packet_id'], 'subject_ids': task['eligible_subject_ids'], 'status': 'reused',
                                      'candidate_ids': [c['candidate_id'] for c in added]})
                    reused_execution('discovery', task['packet_id'], [c['candidate_id'] for c in added], provenance)
                elif len(fresh_discovery) < discovery_limit:
                    fresh_discovery.append(task)
        budget = ai_limit - len(fresh_discovery)
        selected = choose(new_rules, budget) if ai else []
        review_packets, oversized = pack(selected, batch_size)
        inputs = [('candidate', p) for p in review_packets] + [('discovery', p) for p in fresh_discovery]
        by_id = {c['candidate_id']: c for c in candidates}
        def run(mode, packet):
            with configuration_session():
                adapter = (candidate_adapter or execute_candidates) if mode == 'candidate' else (discovery_adapter or execute_discovery)
                return adapter(packet, timeout, model, first_response_timeout)
        if inputs:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                pending = {executor.submit(run, mode, p): (mode, p) for mode, p in inputs}
                for future in as_completed(pending):
                    mode, packet = pending[future]
                    try:
                        result, receipt = future.result()
                        if mode == 'candidate':
                            result = validate_decisions(result, packet)
                            if not verified_receipt(receipt, 'candidate_validation'): raise ValueError('Unverified model execution')
                            for decision in result['reviews']:
                                c = by_id[decision['candidate_id']]
                                cache.put('candidate', unit(c), packet, result, receipt)
                                apply(c, decision, packet['packet_id'])
                            ids = [c['candidate_id'] for c in packet['candidates']]
                        else:
                            result = validate_discovery(result, packet)
                            if not verified_receipt(receipt, 'discovery_validation'): raise ValueError('Unverified discovery execution')
                            added = hypotheses(result, packet, context)
                            for c in added: c['ai']['reused'] = False
                            discovered += added; ids = [c['candidate_id'] for c in added]
                            cache.put('discovery', discovery_unit(packet), packet, result, receipt)
                            task_rows.append({'packet_id': packet['packet_id'], 'subject_ids': packet['eligible_subject_ids'], 'status': 'completed', 'candidate_ids': ids})
                        outputs[packet['packet_id']] = {'result': result, 'execution': receipt}
                        executions.append(dict(receipt, mode=mode, packet_id=packet['packet_id'], candidate_ids=ids, fresh_model_execution=True))
                    except (ReviewFailure, ValueError, KeyError, TypeError, OSError) as error:
                        ids = [c['candidate_id'] for c in packet['candidates']] if mode == 'candidate' else []
                        executions.append({'mode': mode, 'packet_id': packet['packet_id'], 'candidate_ids': ids, 'status': 'failed',
                            'code': error.code if isinstance(error, ReviewFailure) else 'INVALID_CANDIDATE_RESULT',
                            'stage': error.stage if isinstance(error, ReviewFailure) else mode + '_validation',
                            'model_execution_verified': False, 'fresh_model_execution': True, 'target_requests_sent': 0})
                        if mode == 'discovery': task_rows.append({'packet_id': packet['packet_id'], 'subject_ids': packet['eligible_subject_ids'], 'status': 'failed', 'candidate_ids': []})
        # Candidate IDs bind the exact cited evidence; retain all distinct hypotheses.
        distinct = {c['candidate_id']: c for c in discovered}
        candidates += list(distinct.values())
        feedback_summary = apply_feedback(candidates, feedback)
        candidates.sort(key=order); executions.sort(key=lambda e: (e['packet_id'], e['mode'], e['status']))
        task_rows.sort(key=lambda e: e['packet_id'])
        rule_candidates = [c for c in candidates if c['origin'] == 'rule']
        summary = {'ai_eligible_candidates': len(eligible),
            'ai_excluded_surface_count': sum(c['lead_class'] == 'review_surface' for c in rule_candidates) if not include_surfaces else 0,
            'ai_human_dismissed_candidates': sum((c.get('human_review') or {}).get('decision') == 'dismiss' for c in rule_candidates),
            'ai_selected_candidates': len(selected) + len(reused_rules),
            'ai_reviewed_candidates': sum(bool(c['ai']) for c in rule_candidates),
            'ai_reviewed_by_kind': dict(Counter(c['kind'] for c in rule_candidates if c['ai'])),
            'ai_fresh_reviewed_candidates': sum(bool(c['ai']) and not c['ai'].get('reused', False) for c in rule_candidates),
            'ai_reused_candidates': len(reused_rules), 'ai_not_reviewed_candidates': sum(not c['ai'] for c in rule_candidates),
            'ai_failed_packets': sum(e['status'] == 'failed' for e in executions), 'ai_oversized_candidates': len(oversized),
            'ai_new_units_selected': len(selected) + len(fresh_discovery), 'ai_new_unit_budget': ai_limit,
            'model_calls': len(inputs), 'cache_enabled': cache.conn is not None, 'cache_invalid_entries': cache.invalid_entries,
            'cache_write_errors': getattr(cache, 'write_errors', 0), 'discovery_new_tasks': len(fresh_discovery),
            'discovery_reused_tasks': reuse_count, 'discovery_hypotheses': len(distinct),
            'discovery_fresh_hypotheses': sum(not c['ai'].get('reused', False) for c in distinct.values()),
            'discovery_reused_hypotheses': sum(c['ai'].get('reused', False) for c in distinct.values())}
        return {'candidates': candidates, 'summary': summary, 'executions': executions, 'inputs': inputs,
                'outputs': outputs, 'oversized': oversized, 'discovery_tasks': task_rows,
                'discovery_coverage': task_summary, 'feedback_summary': feedback_summary}
    finally:
        cache.close()
