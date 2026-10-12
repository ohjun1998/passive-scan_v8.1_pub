"""Explicit non-secret observation labels; independent of masked credentials."""
import re
from .core import redact_text, digest, response_identity

LABELS = ('actor','tenant','scenario','capture_id','expected_access','operation','parent_observation_id')
STATES = ('discovered','captured','queued','testing','confirmed','false_positive','deferred')


def clean_context(value=None):
    if value is None: return {}
    if not isinstance(value,dict): raise ValueError('Context must be an object')
    result={}
    for key in LABELS:
        text=str(value.get(key,'')).strip()
        if not text: continue
        if len(text)>128 or any(ord(x)<32 for x in text): raise ValueError('Invalid context label')
        if key=='expected_access' and text not in ('allow','deny','unknown'): raise ValueError('Invalid expected access')
        if key=='operation' and text not in ('read','write','unknown'): raise ValueError('Invalid operation')
        if key=='parent_observation_id' and not re.fullmatch('[0-9a-f]{64}',text): raise ValueError('Invalid parent observation')
        result[key]=redact_text(text)
    return result


def attach_context(record,value=None):
    record['context']=clean_context(value)
    # Empty labels keep the original v8.1 ID, preserving old DB/JSONL round trips.
    identity=[record['request_id'],response_identity(record['response']),record['source'],record.get('origin_url')]
    if record['context']: identity.append(record['context'])
    asset=record.get('asset') or {}
    if asset.get('content_hash') and asset.get('analyzer_version'):
        identity.append([asset['content_hash'],asset['analyzer_version']])
    record['observation_id']=digest(identity)
    return record
