"""Bounded, locally checked relationships and exact-source context for recommendations."""
import copy
import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit

from .analysis import comparison_selector, body_values, flows, event_order, ID, INPUT, leaf
from .core import digest, MASK, canonical, get_header
from .candidate_rules import reference, validate_refs, _leaves_of

CONTEXT_VERSION = '8.9.0-2'
MAX_CONTEXT_RECORDS = 3


def record_digest(record):
    # Full saved bodies and security context, not merely the displayed excerpts.
    return digest({k: record.get(k) for k in ('observation_id', 'method', 'url', 'observed', 'headers', 'body',
        'response', 'context', 'authority', 'resource_headers')})


def profile(record):
    return {'observation_id': record['observation_id'], 'method': record['method'], 'url': record['url'],
        'context': record.get('context') or {}, 'authority': record.get('authority') or {},
        'expected_access': ((record.get('authority') or {}).get('policy') or {}).get('expected_access', (record.get('context') or {}).get('expected_access', 'unknown')), 'observed': record.get('observed', False),
        'response_status': (record.get('response') or {}).get('status'),
        'response_content_type': get_header((record.get('response') or {}).get('headers', []), 'content-type'),
        'request_body_complete': bool((record.get('body') or {}).get('complete')),
        'response_body_complete': bool(((record.get('response') or {}).get('body') or {}).get('complete')),
        'request_fields': list((record.get('body') or {}).get('fields', []))[:24],
        'request_fields_omitted': max(0, len((record.get('body') or {}).get('fields', [])) - 24)}


def preview(record, limit=4):
    refs = [reference(record, 'url')]
    for request in (True, False):
        prefix = 'request' if request else 'response'
        leaves = _leaves_of(record, request)
        if leaves:
            refs += [reference(record, prefix + '.body.json', p) for p, _ in leaves[:2]]
        else:
            refs.append(reference(record, prefix + '.body.text'))
    return [r for r in refs if r][:limit]


def difference(left, right):
    a = ((left.get('response') or {}).get('body') or {})
    b = ((right.get('response') or {}).get('body') or {})
    result = {'left_id': left['observation_id'], 'right_id': right['observation_id'],
        'left_status': (left.get('response') or {}).get('status'), 'right_status': (right.get('response') or {}).get('status'),
        'body_comparable': False, 'changed_fields': [], 'omitted_fields': 0}
    refs = []
    if not a.get('complete') or not b.get('complete') or a.get('kind') != b.get('kind'): return result, refs
    result['body_comparable'] = True
    if a.get('kind') == 'json':
        av, bv = dict(_leaves_of(left)), dict(_leaves_of(right))
        changed = [p for p in sorted(set(av) | set(bv)) if p not in av or p not in bv or type(av[p]) is not type(bv[p]) or av[p] != bv[p]]
        result['changed_fields'] = changed[:6]; result['omitted_fields'] = max(0, len(changed) - 6)
        for p in changed[:2]:
            for record, values in ((left, av), (right, bv)):
                if p in values: refs.append(reference(record, 'response.body.json', p))
    elif a.get('text') != b.get('text'):
        result['changed_fields'] = ['saved_body_text']
        first = next((i for i, (x, y) in enumerate(zip(a.get('text', ''), b.get('text', ''))) if x != y), min(len(a.get('text', '')), len(b.get('text', ''))))
        refs = [reference(r, 'response.body.text', start=max(0, first - 60)) for r in (left, right)]
    return result, [r for r in refs if r]


class EvidenceContext:
    def __init__(self, records, analysis=None):
        if len(records) > 10000: raise ValueError('Context record budget exceeded; narrow scope')
        self.records = records
        self.fingerprints = {oid: record_digest(r) for oid, r in records.items()}
        self.selectors = {}; self.exact = defaultdict(list); self.variants = defaultdict(list)
        self.edges = defaultdict(list); self.groups = {}
        for oid, r in records.items():
            selector = comparison_selector(r); self.selectors[oid] = selector
            if not selector['uncertain']: self.exact[selector['key']].append(oid)
            u = urlsplit(r['url']); c = r.get('context') or {}
            # No body/path identifier normalization: different object inputs stay visible.
            key = digest([r['method'], u.scheme, u.netloc, u.path,
                          [(name, get_header(r.get('headers', []), name)) for name in r.get('resource_headers', [])],
                          c.get('actor'), c.get('tenant'), c.get('capture_id'), c.get('scenario')])
            self.groups[oid] = key
            if c.get('capture_id') and r.get('observed'): self.variants[key].append(oid)
        for groups in (self.exact, self.variants):
            for key, ids in groups.items(): ids.sort(key=lambda oid: event_order(records[oid]), reverse=True)
        self.group_digests = {('exact', key): digest([(oid, self.fingerprints[oid]) for oid in ids]) for key, ids in self.exact.items()}
        self.group_digests.update({('variant', key): digest([(oid, self.fingerprints[oid]) for oid in ids]) for key, ids in self.variants.items()})
        saved_flows = (analysis or {}).get('flows')
        if saved_flows is None: saved_flows = flows(list(records.values()))
        if not isinstance(saved_flows, list) or len(saved_flows) > 10000: raise ValueError('Invalid saved flow context')
        checked = 0
        for flow in saved_flows:
            if not isinstance(flow, dict): continue
            links = flow.get('links', [])
            if not isinstance(links, list): raise ValueError('Invalid saved flow links')
            for link in links:
                if not isinstance(link, dict): raise ValueError('Invalid saved flow link')
                checked += 1
                if checked > 20000: raise ValueError('Flow context budget exceeded')
                before = records.get(link.get('from_id')); after = records.get(link.get('to_id'))
                if not before or not after or before is after: continue
                ac, bc = before.get('context') or {}, after.get('context') or {}
                if not ac.get('actor') or not ac.get('capture_id') or any(ac.get(k) != bc.get(k) for k in ('actor', 'tenant', 'capture_id', 'scenario')): continue
                outgoing = body_values((before.get('response') or {}).get('body') or {})
                incoming = body_values(after.get('body') or {})
                incoming.update({'query.' + k: v for k, v in parse_qsl(urlsplit(after['url']).query)})
                incoming.update({'path.' + str(i): v for i, v in enumerate(urlsplit(after['url']).path.split('/')) if v})
                field, destination = link.get('response_field'), link.get('request_field')
                if not isinstance(field, str) or not (ID.match(leaf(field)) or INPUT.match(leaf(field))): continue
                value, target = outgoing.get(field), incoming.get(destination)
                if value is None or isinstance(value, bool) or MASK in str(value) or str(value) != str(target): continue
                relation = {'kind': 'inferred_value_flow', 'from_id': before['observation_id'], 'to_id': after['observation_id'],
                    'response_field': field, 'request_field': destination,
                    'from_event_id': link.get('from_event_id') if type(link.get('from_event_id')) is int else None,
                    'to_event_id': link.get('to_event_id') if type(link.get('to_event_id')) is int else None,
                    'chronology': flow.get('chronology') if flow.get('chronology') in ('capture_events', 'deduplicated_observations') else 'unverified_source_chronology',
                    'warning': '값 일치와 저장 순서의 추정 연결이며 실제 서버 의존 관계·반복 순서의 증명이 아닙니다.'}
                self.edges[before['observation_id']].append(relation)
                self.edges[after['observation_id']].append(relation)

    def related(self, subject_ids, support_ids=(), support_role='normal_control'):
        subjects = set(subject_ids); chosen = []; relations = []; dependencies = []
        def include(oid, relation):
            if oid in self.records and oid not in subjects and oid not in chosen:
                chosen.append(oid); relations.append(dict(relation, related_id=oid))
        for oid in subject_ids:
            r = self.records[oid]; selector = self.selectors[oid]
            identity = (r.get('authority') or {}).get('identity') or {}
            if identity.get('observation_id'):
                include(identity['observation_id'], {'kind': 'saved_identity_support', 'subject_id': oid})
            for sid in support_ids: include(sid, {'kind': support_role, 'subject_id': oid})
            for edge in self.edges.get(oid, []):
                include(edge['to_id'] if edge['from_id'] == oid else edge['from_id'], edge)
                dependencies.append(digest([edge, self.fingerprints[edge['from_id']], self.fingerprints[edge['to_id']]]))
            if not selector['uncertain']:
                dependencies.append(self.group_digests.get(('exact', selector['key'])))
                for other in self.exact.get(selector['key'], []):
                    include(other, {'kind': 'matching_saved_selectors', 'subject_id': oid,
                                    'warning': '저장 선택값 일치이며 실제 신원·권한 검증은 아닙니다.'})
            key = self.groups[oid]; dependencies.append(self.group_digests.get(('variant', key)))
            for other in self.variants.get(key, []):
                include(other, {'kind': 'saved_request_variant', 'subject_id': oid,
                                'warning': '같은 기능·수집 맥락의 입력 변형이며 동일 자원이라고 가정하지 않습니다.'})
        return chosen, relations, digest(dependencies)

    def bundle(self, subject_ids, support_ids=(), seed_evidence=(), support_role='normal_control'):
        related, relations, dependency = self.related(subject_ids, support_ids, support_role)
        preferred = list(dict.fromkeys([*support_ids, *related]))
        selected = list(subject_ids) + [oid for oid in preferred if oid not in subject_ids][:max(0, MAX_CONTEXT_RECORDS - len(subject_ids))]
        refs = list(copy.deepcopy(seed_evidence)); diffs = []
        for oid in selected:
            refs += preview(self.records[oid], 3)
        for sid in subject_ids:
            for oid in selected:
                if oid != sid:
                    diff, anchors = difference(self.records[sid], self.records[oid]); diffs.append(diff); refs += anchors
        unique = {}; seed_keys = {digest(r) for r in seed_evidence}
        for ref in refs:
            if ref: unique.setdefault(digest(ref), ref)
        # Candidate's own evidence is already in the model input; only add context anchors.
        extra = [r for key, r in unique.items() if key not in seed_keys][:12]
        bundle = {'context_version': CONTEXT_VERSION, 'records': [profile(self.records[oid]) for oid in selected],
            'relations': [rel for rel in relations if rel['related_id'] in selected][:6], 'response_differences': diffs[:4],
            'evidence': extra, 'omitted_related_records': max(0, len(related) - len(selected) + len(subject_ids)),
            'omitted_context_evidence': max(0, len(unique) - len(seed_keys) - len(extra)),
            'dependency_sha256': dependency,
            'notice': '저장 자료의 비교·흐름 맥락입니다. 관련 자료를 의심 대상이나 정상 대조군으로 자동 변경하지 않습니다.'}
        bundle['evidence_digest'] = digest([CONTEXT_VERSION, [(oid, self.fingerprints[oid]) for oid in selected], dependency, bundle])
        validate_refs({'subject_ids': list(subject_ids), 'support_ids': sorted(({oid for oid in selected} | {ref['observation_id'] for ref in seed_evidence}) - set(subject_ids)),
                       'evidence': list(seed_evidence) + extra}, self.records)
        return bundle

    def attach(self, candidates):
        for c in candidates:
            c['origin'] = 'rule'
            c['evidence_bundle'] = self.bundle(c['subject_ids'], c['support_ids'], c['evidence'])
            c['evidence_digest'] = c['evidence_bundle']['evidence_digest']
        return candidates


def display_record(record):
    """Portable masked display copy; explicit byte limits never change source evidence."""
    value = {k: copy.deepcopy(record[k]) for k in ('observation_id', 'url', 'method', 'headers', 'context', 'authority', 'observed') if k in record}
    def body(source):
        source = source or {}; text = source.get('text', ''); encoded = text.encode()
        out = {k: copy.deepcopy(source[k]) for k in ('kind', 'complete', 'reason') if k in source}
        out.update(text=encoded[:16384].decode('utf-8', errors='ignore'), fields=list(source.get('fields', []))[:128],
                   original_saved_complete=bool(source.get('complete')), saved_text_sha256=digest(text),
                   display_omitted_bytes=max(0, len(encoded) - 16384))
        if out['display_omitted_bytes']: out.update(complete=False, reason='display_byte_limit')
        return out
    value['body'] = body(record.get('body'))
    response = record.get('response')
    value['response'] = None if not response else {'status': response.get('status'), 'headers': copy.deepcopy(response.get('headers', [])), 'body': body(response.get('body'))}
    value['notice'] = 'Display-only masked snapshot, not a complete new capture or target request.'
    return value
