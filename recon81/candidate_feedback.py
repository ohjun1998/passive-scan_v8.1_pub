"""Explicit human decisions bound to an immutable recommendation and evidence digest."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from .ai_review import load_json, read_bytes, bounded_json, AGGREGATE_LIMIT, _no_duplicates
from .core import private_write, now, invalid_json_constant
from .candidate_rules import scrub
from .locking import advisory_file_lock

DECISIONS = ('follow_up', 'dismiss', 'needs_context')
HEX = re.compile(r'[a-f0-9]{64}')


def read_feedback(path):
    if path is None: return {'schema_version': '8.9', 'entries': []}
    value = load_json(path, AGGREGATE_LIMIT)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'entries'} or value['schema_version'] != '8.9':
        raise ValueError('Invalid candidate feedback document')
    if not isinstance(value['entries'], list) or len(value['entries']) > 10000: raise ValueError('Feedback budget exceeded')
    for e in value['entries']:
        if not isinstance(e, dict) or set(e) != {'candidate_id','evidence_digest','decision','note','reviewed_at','source_report_sha256','provenance'}:
            raise ValueError('Invalid feedback entry')
        if any(not isinstance(e[k], str) or not HEX.fullmatch(e[k]) for k in ('candidate_id','evidence_digest','source_report_sha256')):
            raise ValueError('Invalid feedback evidence identity')
        if (e['decision'] not in DECISIONS or e['provenance'] != 'human_cli' or not isinstance(e['note'], str) or len(e['note']) > 2000 or
            not isinstance(e['reviewed_at'], str) or len(e['reviewed_at']) > 64): raise ValueError('Invalid human decision')
    return scrub(value)


def save_feedback(review, candidate_id, decision, note, output):
    if decision not in DECISIONS or not isinstance(note, str) or not 1 <= len(note.strip()) <= 2000:
        raise ValueError('Human decision and explanation required')
    review = Path(review); manifest = load_json(review / 'manifest.json')
    data = read_bytes(review / 'recommendations.json', AGGREGATE_LIMIT)
    sha = hashlib.sha256(data).hexdigest()
    if (manifest.get('files') or {}).get('recommendations.json') != sha: raise ValueError('Recommendation manifest mismatch')
    report = json.loads(data, parse_constant=invalid_json_constant, object_pairs_hook=_no_duplicates)
    candidate = next((c for c in report['candidates'] if c['candidate_id'] == candidate_id), None)
    if candidate is None or not HEX.fullmatch(candidate.get('evidence_digest', '')): raise ValueError('Unknown candidate or missing evidence identity')
    output = Path(output)
    if output.is_symlink(): raise ValueError('Feedback output must not be a symlink')
    if output.resolve().is_relative_to(review.resolve()): raise ValueError('Feedback must be separate from source review')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with advisory_file_lock(output.with_name(output.name + '.lock'), 'Another feedback writer is running'):
        value = read_feedback(output) if output.exists() else read_feedback(None)
        if len(value['entries']) >= 10000: raise ValueError('Feedback entry budget exceeded')
        entry = {'candidate_id': candidate_id, 'evidence_digest': candidate['evidence_digest'], 'decision': decision,
                 'note': scrub(note.strip()), 'reviewed_at': now(), 'source_report_sha256': sha, 'provenance': 'human_cli'}
        value['entries'].append(entry)
        private_write(output, bounded_json(value, AGGREGATE_LIMIT))
    return entry


def apply_feedback(candidates, value):
    latest = {(e['candidate_id'], e['evidence_digest']): e for e in value['entries']}
    current = {(c['candidate_id'], c['evidence_digest']) for c in candidates}
    counts = Counter()
    for c in candidates:
        e = latest.get((c['candidate_id'], c['evidence_digest']))
        c['human_review'] = e
        if e: counts[e['decision']] += 1
    return {'applied': sum(counts.values()), 'by_decision': dict(counts),
        'stale_or_unmatched_entries': sum(key not in current for key in latest),
        'notice': 'Human follow-up value, not confirmed vulnerability labels. Only exact saved evidence matches apply.'}
