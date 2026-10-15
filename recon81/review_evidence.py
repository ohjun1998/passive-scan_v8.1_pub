"""v8.5 saved-evidence fragments, explicit authority links and verifiable citations."""
import copy
import json
import re
from urllib.parse import urlsplit
from .core import canonical, digest, sanitize_value, invalid_json_constant, safe_url
from .ai_review import SCHEMA, HEX, _evidence, _json, _validate_schema

CITATION = {'type':'object','properties':{
    'observation_id':{'type':'string','pattern':HEX},
    'location':{'type':'string','enum':['response.body.json','request.body.json','response.body.text','request.body.text','response.headers','request.headers','context','authority']},
    'pointer':{'type':'string','maxLength':512},'excerpt':{'type':'string','maxLength':1000}},
    'required':['observation_id','location','pointer','excerpt'],'additionalProperties':False}
SCHEMA85 = copy.deepcopy(SCHEMA)
SCHEMA85['properties']['reviews']['items']['properties']['citations']={'type':'array','maxItems':30,'items':CITATION}
SCHEMA85['properties']['reviews']['items']['required'].append('citations')


def pointer(value, path):
    """Strict RFC 6901. No wildcards, negative indices or inferred paths."""
    if path=='':return value
    if not isinstance(path,str) or not path.startswith('/') or re.search(r'~(?![01])',path):
        raise ValueError('Invalid JSON pointer')
    for part in path[1:].split('/'):
        part=part.replace('~1','/').replace('~0','~')
        try:
            if isinstance(value,dict):value=value[part]
            elif isinstance(value,list) and re.fullmatch(r'0|[1-9][0-9]*',part):value=value[int(part)]
            else:raise ValueError('Missing JSON pointer')
        except (KeyError,IndexError,TypeError):raise ValueError('Missing JSON pointer') from None
    return value


def _leaves(value,path='',depth=0,counter=None):
    counter=counter if counter is not None else [0]
    counter[0]+=1
    if depth>32 or counter[0]>50000:raise ValueError('Structured body complexity limit')
    if isinstance(value,dict) and value:
        for key,child in value.items():
            yield from _leaves(child,path+'/'+key.replace('~','~0').replace('/','~1'),depth+1,counter)
    elif isinstance(value,list) and value:
        for index,child in enumerate(value):yield from _leaves(child,path+'/'+str(index),depth+1,counter)
    else:yield path,value


def _chunks(text,size):
    current=[];used=0
    for character in text:
        cost=len(character.encode('utf-8'))
        if used+cost>size:
            yield ''.join(current);current=[];used=0
        current.append(character);used+=cost
    if current:yield ''.join(current)


def split_body(body,size,max_fragments=None):
    if size < 1 or max_fragments is not None and max_fragments < 1:
        raise ValueError('Invalid fragment budget')
    fragments=[]
    def append(fragment):
        if max_fragments is not None and len(fragments)>=max_fragments:
            raise ValueError('Body fragment budget exceeded')
        fragments.append(fragment)
    result=sanitize_value({k:copy.deepcopy(body[k]) for k in ('kind','complete','reason','size_bytes') if k in body})
    text=body.get('text','')
    if not isinstance(text,str):raise ValueError('Invalid body text')
    text=sanitize_value(text)
    if body.get('kind')=='json':
        try:value=sanitize_value(json.loads(body.get('text',''),parse_constant=invalid_json_constant))
        except (ValueError,RecursionError):
            if body.get('complete'):raise ValueError('Malformed JSON source body') from None
            for part in _chunks(text,size):
                append(dict(result,kind='text_fragment',text=part,fields=[],complete=False,reason='source_json_partial'))
            return fragments or [dict(result,kind='text_fragment',text='',fields=[],complete=False,reason='source_json_partial')]
        text=_json(value)
    if len(text.encode())<=size:
        result.update(text=text,fields=sanitize_value(list(body.get('fields',[]))[:128]))
        return [result]
    source_hash=digest(text)
    if body.get('kind')!='json':
        for i,part in enumerate(_chunks(text,size)):
            append(dict(result,kind='text_fragment',text=part,fields=[],complete=False,reason='ai_text_fragment',
                        fragment_index=i,source_body_sha256=source_hash))
        return fragments
    values={}
    def flush():
        nonlocal values
        if values:
            append(dict(result,kind='json_fragment',values=values,text=_json(values),fields=list(values),
                        complete=False,reason='ai_json_fragment',source_body_sha256=source_hash))
            values={}
    for path,child in _leaves(value):
        candidate=dict(values);candidate[path]=child
        if len(_json(candidate).encode())>size:
            flush()
            if len(_json({path:child}).encode())>size:
                for part in _chunks(child if isinstance(child,str) else canonical(child),size):
                    append(dict(result,kind='text_fragment',text=part,fields=[path],complete=False,
                        reason='ai_json_value_fragment',origin_pointer=path,source_body_sha256=source_hash))
                continue
        values[path]=child
    flush()
    for i,fragment in enumerate(fragments):fragment['fragment_index']=i
    return fragments


def expand_record(record,scope,body_bytes,max_fragments=None):
    item=_evidence(record,scope)
    request=split_body(record.get('body') or {},body_bytes,max_fragments)
    response=split_body((record.get('response') or {}).get('body') or {},body_bytes,max_fragments) if record.get('response') else [None]
    count=max(len(request),len(response))
    for index in range(count):
        part=copy.deepcopy(item);part['body']=request[min(index,len(request)-1)]
        if response[0] is not None:part['response']['body']=response[min(index,len(response)-1)]
        part['fragment']={'index':index,'count':count,'request_index':min(index,len(request)-1),
            'response_index':min(index,len(response)-1),'original_response_complete':bool((record.get('response') or {}).get('body',{}).get('complete'))}
        part['fragment']['id']=digest([part['observation_id'],index,part['body'],part.get('response')])
        # Full triage field lists can exceed the actual body; keep explicit metadata omissions.
        triage=part.get('triage') or {}
        part['triage']={k:v for k,v in triage.items() if k in ('score','priority','missing','conclusion')}
        yield part


def group_key(record):
    context=sanitize_value(record.get('context') or {})
    url=safe_url(record['url'])
    route=re.sub(r'(?<=/)[0-9]+(?=/|$)','{id}',urlsplit(url).path)
    return canonical([urlsplit(url).netloc,context.get('scenario') or sanitize_value(record['method'])+' '+route])


def authority_links(records,configuration,scope):
    if configuration is None:return {},{}
    if set(configuration)!={'identities','policies'} or not isinstance(configuration['identities'],list) or not isinstance(configuration['policies'],list):
        raise ValueError('Invalid authority configuration')
    if len(configuration['identities'])>100 or len(configuration['policies'])>1000:raise ValueError('Authority configuration limit')
    by_id={r['observation_id']:r for r in records};identities={};supports={}
    for spec in configuration['identities']:
        keys={'actor','observation_id','user_pointer','role_pointer','expected_user_id','expected_role','provenance'}
        if set(spec)!=keys or not spec['provenance'] or len(spec['provenance'])>512:raise ValueError('Identity requires provenance')
        record=by_id.get(spec['observation_id'])
        if not record or not record.get('observed') or not scope.allows(record['url']) or record.get('context',{}).get('actor')!=spec['actor']:
            raise ValueError('Identity evidence not in scope or actor mismatch')
        response=record.get('response') or {};body=response.get('body') or {}
        if body.get('kind')!='json' or not body.get('complete') or not 200<=response.get('status',0)<300:
            raise ValueError('Identity response incomplete or unsuccessful')
        value=json.loads(body['text'],parse_constant=invalid_json_constant);uid=pointer(value,spec['user_pointer']);role=pointer(value,spec['role_pointer'])
        if type(uid)!=type(spec['expected_user_id']) or uid!=spec['expected_user_id'] or role!=spec['expected_role']:
            raise ValueError('Identity value mismatch')
        if spec['actor'] in identities:raise ValueError('Duplicate actor identity')
        identities[spec['actor']]=sanitize_value(dict(spec,observed_user_id=uid,observed_role=role,
            status='corroborated_saved_response',session_continuity_verified=False))
        support=_evidence(record,scope)
        values={spec['user_pointer']:sanitize_value(uid),spec['role_pointer']:sanitize_value(role)}
        support['response']['body']={'kind':'json_fragment','values':values,'text':_json(values),'fields':list(values),
                                     'complete':False,'reason':'identity_fields_selected'}
        support['fragment']={'index':0,'count':1,'id':digest([record['observation_id'],'identity_support']),'support_only':True}
        identities[spec['actor']]['session_continuity_verified']=False
        supports[record['observation_id']]=support
    policies={}
    for spec in configuration['policies']:
        if set(spec)!={'observation_ids','owner','allowed_actors','expected_access','provenance'} or spec['expected_access'] not in ('allow','deny','unknown'):
            raise ValueError('Invalid expected policy')
        if not isinstance(spec['allowed_actors'],list) or len(spec['allowed_actors'])>100 or not spec['provenance'] or len(spec['provenance'])>512:
            raise ValueError('Policy requires bounded provenance and actors')
        if not isinstance(spec['observation_ids'],list) or len(spec['observation_ids'])>1000 or any(not isinstance(a,str) for a in spec['allowed_actors']):raise ValueError('Invalid policy IDs or actors')
        for oid in spec['observation_ids']:
            if oid not in by_id or not scope.allows(by_id[oid]['url']) or oid in policies:raise ValueError('Policy evidence missing, outside scope or duplicate')
            actor=by_id[oid].get('context',{}).get('actor')
            if spec['expected_access']!='unknown' and (actor in spec['allowed_actors'])!=(spec['expected_access']=='allow'):
                raise ValueError('Declared access contradicts allowed actors')
            policies[oid]=sanitize_value({k:v for k,v in spec.items() if k!='observation_ids'})
    links={}
    for record in records:
        oid=record['observation_id'];actor=record.get('context',{}).get('actor')
        identity=copy.deepcopy(identities.get(actor))
        if identity:
            identity_record=by_id[identity['observation_id']]
            a=(record.get('context') or {}).get('capture_id');b=(identity_record.get('context') or {}).get('capture_id')
            identity['capture_link_status']='same_capture_label' if a and b and a==b else 'different_or_missing_capture_label'
        links[oid]={'identity':identity,'policy':policies.get(oid),
                    'policy_status':'declared_with_provenance' if oid in policies else 'not_provided'}
    return links,supports


def validate_citations(result,packet):
    _validate_schema(result,SCHEMA85)
    by_id={r['observation_id']:r for r in packet['evidence']}
    verified=[]
    for index,review in enumerate(result['reviews']):
        if review['assessment']!='insufficient_evidence' and not review['citations']:
            raise ValueError('An assessment requires at least one verified citation')
        for cite in review['citations']:
            if cite['observation_id'] not in review['observation_ids'] or cite['observation_id'] not in by_id or not cite['excerpt']:
                raise ValueError('Citation must reference this review and packet')
            record=by_id[cite['observation_id']];location=cite['location'];path=cite['pointer'];excerpt=cite['excerpt']
            if location in ('response.headers','request.headers'):
                headers=(record.get('response') or {}).get('headers',[]) if location=='response.headers' else record.get('headers',[])
                value=pointer(headers,path);actual=value if isinstance(value,str) else canonical(value);valid=actual==excerpt
            elif location in ('context','authority'):
                value=pointer(record.get(location) or {},path)
                actual=value if isinstance(value,str) else canonical(value)
                valid=actual==excerpt
            else:
                body=(record.get('response') or {}).get('body') if location.startswith('response') else record.get('body')
                if not body:raise ValueError('Citation references missing body')
                if location.endswith('.json'):
                    if body.get('kind')=='json_fragment':value=body.get('values',{})[path]
                    elif body.get('kind')=='json' and body.get('complete'):value=pointer(json.loads(body['text'],parse_constant=invalid_json_constant),path)
                    else:raise ValueError('Citation JSON body is unavailable or incomplete')
                    actual=value if isinstance(value,str) else canonical(value);valid=actual==excerpt
                else:
                    valid=path=='' and excerpt in body.get('text','')
            if not valid:raise ValueError('Citation excerpt does not match saved evidence')
            verified.append({'review_index':index,**cite,'masked': '[REDACTED]' in excerpt,
                             'meaning_or_vulnerability_verified':False})
    return verified
