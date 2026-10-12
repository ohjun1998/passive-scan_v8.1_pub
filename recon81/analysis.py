"""Evidence-driven triage, exact-resource actor comparison and coverage. Offline only."""
import itertools
import json
import re
from collections import Counter,defaultdict
from urllib.parse import urlsplit,parse_qsl
from .core import digest, get_header, MASK

ID=re.compile(r'^(?:id|uuid|user_?id|owner_?id|account_?id|tenant_?id|org_?id|order_?id|file_?id|document_?id|project_?id|role|permissions?)$',re.I)
INPUT=re.compile(r'^(?:url|uri|callback|redirect|destination|path|filename|file_url|fileUrl)$',re.I)


def leaf(path): return re.split(r'[.\[\]/]',path)[-1]


def flatten(value,path='$',depth=0):
    if depth>12: return {}
    if isinstance(value,dict):
        out={}
        for k,v in list(value.items())[:200]: out.update(flatten(v,path+'.'+str(k),depth+1))
        return out
    if isinstance(value,list):
        out={}
        for i,v in enumerate(value[:100]): out.update(flatten(v,path+'['+str(i)+']',depth+1))
        return out
    return {path:value}


def body_values(body):
    try:
        if body['kind']=='json': return flatten(json.loads(body['text']))
        if body['kind']=='form': return {'$.'+k:v for k,v in parse_qsl(body['text'],keep_blank_values=True)}
        if body['kind']=='multipart': return {'$.'+p['name']:p.get('value') for p in body.get('parts',[]) if 'value' in p}
    except (ValueError,TypeError,KeyError,RecursionError): pass
    return {}


def route(record):
    p=urlsplit(record['url'])
    path=re.sub(r'(?<=/)(?:[0-9]+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?=/|$)','{id}',p.path)
    template=(record.get('schema') or {}).get('path_template')
    if template: path=re.sub(r'\{[^}]+\}','{id}',p.path)
    return p.scheme+'://'+p.netloc+path


def triage(record):
    context=record.get('context') or {}; fields=list(record['body']['fields'])
    fields += [k for k,_ in parse_qsl(urlsplit(record['url']).query)]
    schema=record.get('schema') or {}
    fields += [p['name'] for p in schema.get('parameters',[]) if isinstance(p,dict) and 'name' in p]
    response=record.get('response') or {}; response_fields=(response.get('body') or {}).get('fields',[])
    hints=[]; score=0
    def add(kind,weight,reason,next_check):
        nonlocal score
        hints.append({'kind':kind,'reason':reason,'next_check':next_check}); score+=weight
    identity=[f for f in fields if ID.match(leaf(f))]
    if identity:
        add('authorization',20,'식별자·권한 필드: '+', '.join(identity[:8]),'자원 소유자와 계정별 기대 권한을 정의하고 같은 자원 응답 비교')
        if any(ID.match(leaf(f)) for f in response_fields):
            add('ownership_evidence',15,'응답에도 식별자·소유자 관련 필드가 관찰됨','요청 식별자와 반환된 자원의 관계 확인')
    if re.search(r'/[0-9]+(?:/|$)',urlsplit(record['url']).path):
        add('resource_identifier',10,'경로에 숫자 식별자가 있음','단순 숫자 경로인지 자원 식별자인지 확인')
    if record['body']['kind']=='multipart' or any('multipart' in x for x in schema.get('content_types',[])):
        add('upload',25,'파일 업로드 요청 또는 명세가 확보됨','업로드 응답의 파일 ID/URL과 조회·다운로드 흐름 연결')
        if any(INPUT.match(leaf(f)) for f in response_fields):
            add('file_access',15,'응답에 URL·파일 경로 필드가 있음','파일 URL 접근 시 사용자별 권한 확인')
    inputs=[f for f in fields if INPUT.match(leaf(f))]
    if inputs:
        add('input_handling',10,'URL·경로 입력: '+', '.join(inputs[:8]),'서버가 이 값을 어떤 기능에 사용하는지 확인')
        if re.search(r'import|fetch|preview|webhook|외부|미리보기',context.get('scenario',''),re.I):
            add('external_fetch_context',15,'기능 라벨에도 외부 URL 처리 맥락이 있음','외부 자료 가져오기 기능의 허용 대상과 처리 결과 확인')
    if re.search(r'(?:/|\b)(?:admin|manage|internal)(?:/|\b)',record['url'],re.I):
        add('privileged_function',10,'관리 기능처럼 보이는 경로가 발견됨','명칭만으로 확정하지 않고 실제 기능과 기대 접근 권한 확인')
    if context.get('expected_access')=='deny' and record['observed'] and 200<=response.get('status',0)<300:
        add('expected_access_mismatch',25,'검토자가 차단을 기대한 관찰에 2xx 응답이 있음','로그인 페이지·공통 응답·실제 민감 데이터 반환 여부를 구분')
    missing=[]
    if not record['observed']: missing.append('실제 요청 미확보')
    if record['method']=='UNKNOWN': missing.append('메소드 미확인')
    if not record['body']['complete']: missing.append('요청 body 값 미수집/부분 표현')
    if not response or not response.get('status'): missing.append('응답 미수집')
    elif not response['body']['complete']: missing.append('응답 body 미수집/생략')
    if not context.get('actor'): missing.append('계정 라벨 없음')
    if record['source']=='httpx_deferred': missing.append('프로빙 예산으로 보류됨')
    if context.get('expected_access','unknown')=='unknown': missing.append('기대 권한 미정')
    if hints:
        score+=10 if record['observed'] else 0
        score+=10 if response and response.get('body',{}).get('complete') else 0
    return {'score':min(score,100),'priority':'high' if score>=60 else 'medium' if score>=30 else 'low','hints':hints,'missing':missing,'conclusion':'review_candidate' if hints else 'insufficient_signals','not_a_vulnerability_verdict':True}


def comparison_key(record):
    # Compare the exact resource and payload, not two different users' own resources.
    body=record['body']['text']
    if record['body']['kind']=='json':
        try: body=json.loads(body)
        except ValueError: pass
    return digest([record['url'],record['method'],record['body']['kind'],body,record['body']['fields'],[(h,get_header(record['headers'],h)) for h in ('content-type','accept','accept-language')]])


def comparison_values(body):
    """Compare every value within a budget; never silently drop late array items."""
    if body['kind']=='form':
        result=defaultdict(list)
        for key,value in parse_qsl(body['text'],keep_blank_values=True): result['$.'+key].append(value)
        return dict(result)
    value=json.loads(body['text']); result={}; visits=0
    def walk(value,path='$',depth=0):
        nonlocal visits
        visits+=1
        if visits>12000 or depth>32: raise ValueError('Comparison complexity limit')
        if isinstance(value,dict) and value:
            for key,child in value.items():
                field='.'+key if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key) else '['+json.dumps(key,ensure_ascii=False)+']'
                walk(child,path+field,depth+1)
        elif isinstance(value,list) and value:
            for index,child in enumerate(value): walk(child,path+'['+str(index)+']',depth+1)
        else: result[path]=value
    walk(value)
    return result


def response_diff(left,right,ignore_fields=()):
    a,b=left.get('response'),right.get('response')
    result={'comparable':False,'differences':[],'omitted_differences':0,'ignored_fields':list(ignore_fields),'warning':'마스킹된 값은 같아 보여도 원래 값이 다를 수 있습니다. 응답 차이는 취약점 확정이 아닙니다.'}
    if not a or not b or not a.get('status') or not b.get('status'):
        result['reason']='missing_response'; return result
    if a['status']!=b['status']: result['differences'].append({'field':'HTTP.status','left':a['status'],'right':b['status']})
    if not a['body']['complete'] or not b['body']['complete']:
        result['reason']='incomplete_response_body'; return result
    if a['body']['kind']!=b['body']['kind']:
        result['reason']='different_body_kinds'; return result
    if a['body']['kind'] in ('json','form'):
        try: av,bv=comparison_values(a['body']),comparison_values(b['body'])
        except (ValueError,TypeError,RecursionError):
            result['reason']='comparison_complexity_limit'; return result
        for field in sorted(set(av)|set(bv)):
            if field in ignore_fields: continue
            if field not in av or field not in bv or av.get(field)!=bv.get(field) or type(av.get(field))!=type(bv.get(field)):
                if len(result['differences'])<100: result['differences'].append({'field':field,'left':av.get(field),'right':bv.get(field),'left_missing':field not in av,'right_missing':field not in bv})
                else: result['omitted_differences']+=1
    elif a['body']['text']!=b['body']['text']:
        result['differences'].append({'field':'body.text','left':a['body']['text'][:4000],'right':b['body']['text'][:4000]})
    result.update(comparable=True,reason='normalized_body_compared')
    return result


def comparisons(records,ignore_fields=(),max_pairs=1000):
    groups=defaultdict(list); output=[]; truncated=0
    for r in records:
        if r['observed'] and r['body']['complete'] and (r.get('context') or {}).get('actor'): groups[comparison_key(r)].append(r)
    for group in groups.values():
        # Preserve all evidence records; only cap the derived comparison view.
        group=sorted(group,key=lambda r:r.get('timestamp',''),reverse=True)
        principals=defaultdict(list)
        for r in group: principals[(r['context']['actor'],r['context'].get('tenant',''))].append(r)
        selected=[items[0] for items in principals.values()][:30]
        selected += [r for items in principals.values() for r in items[1:]][:30-len(selected)]
        if len(group)>len(selected): truncated+=len(group)-len(selected)
        for a,b in itertools.combinations(selected,2):
            ac,bc=a['context'],b['context']
            if (ac['actor'],ac.get('tenant',''))==(bc['actor'],bc.get('tenant','')): continue
            if len(output)>=max_pairs: truncated+=1; continue
            output.append({'url':a['url'],'method':a['method'],'left_id':a['observation_id'],'right_id':b['observation_id'],'left_actor':ac['actor'],'right_actor':bc['actor'],'left_tenant':ac.get('tenant',''),'right_tenant':bc.get('tenant',''),'left_expected':ac.get('expected_access','unknown'),'right_expected':bc.get('expected_access','unknown'),**response_diff(a,b,ignore_fields)})
    return output,truncated


def flows(records):
    groups=defaultdict(list)
    for r in records:
        c=r.get('context') or {}
        if c.get('capture_id') and c.get('scenario') and r['observed']:
            groups[(c.get('actor',''),c.get('tenant',''),c['scenario'],c['capture_id'])].append(r)
    output=[]
    for (actor,tenant,scenario,capture),group in groups.items():
        group=sorted(group,key=lambda r:r.get('timestamp',''))
        links=[]; previous=[]
        for r in group[:500]:
            p=urlsplit(r['url']); incoming=body_values(r['body']); incoming.update({'query.'+k:v for k,v in parse_qsl(p.query)})
            incoming.update({'path.'+str(i):v for i,v in enumerate(p.path.split('/')) if v})
            for before in previous[-20:]:
                outgoing=body_values((before.get('response') or {}).get('body',{}))
                for source,value in outgoing.items():
                    if not (ID.match(leaf(source)) or INPUT.match(leaf(source))) or value is None or isinstance(value,bool) or MASK in str(value): continue
                    for destination,target in incoming.items():
                        if str(value)==str(target) and str(value):
                            links.append({'from_id':before['observation_id'],'to_id':r['observation_id'],'response_field':source,'request_field':destination,'confidence':'inferred_value_match'})
                            break
                    if len(links)>=200: break
                if len(links)>=200: break
            previous.append(r)
        output.append({'actor':actor,'tenant':tenant,'scenario':scenario,'capture_id':capture,'steps':[{'observation_id':r['observation_id'],'method':r['method'],'url':r['url'],'timestamp':r['timestamp']} for r in group[:500]],'links':links[:200],'truncated_steps':max(0,len(group)-500),'warning':'값 일치로 추정한 연결이며 서버의 실제 의존 관계를 증명하지 않습니다.'})
    return output


def analyze(records,ignore_fields=()):
    enriched=[]; coverage=defaultdict(list)
    for r in records:
        r=dict(r); r.setdefault('context',{}); r.setdefault('review',{'state':'captured' if r['observed'] else 'discovered','note':''})
        r['triage']=triage(r); r['route_group']=route(r); enriched.append(r)
        key=digest([r['route_group'],r['method'],sorted(k for k,_ in parse_qsl(urlsplit(r['url']).query)),r['body']['fields']])
        coverage[key].append(r)
    pairs,truncated=comparisons(enriched,ignore_fields)
    rows=[]
    for group in coverage.values():
        terminal=sum(r['review']['state'] in ('confirmed','false_positive') for r in group)
        rows.append({'route':group[0]['route_group'],'method':group[0]['method'],'records':len(group),'observed':sum(r['observed'] for r in group),'actors':sorted({r['context']['actor'] for r in group if r['context'].get('actor')}),'states':dict(Counter(r['review']['state'] for r in group)),'coverage':'reviewed' if terminal==len(group) else 'partial_review' if terminal else 'captured' if any(r['observed'] for r in group) else 'discovered','missing':sorted({x for r in group for x in r['triage']['missing']}),'observation_ids':[r['observation_id'] for r in group]})
    summary={'records':len(records),'observed':sum(r['observed'] for r in records),'candidates':sum(bool(r['triage']['hints']) for r in enriched),'unreviewed':sum(r['review']['state'] not in ('confirmed','false_positive') for r in enriched),'missing_response':sum(not r.get('response') or not r['response'].get('status') for r in enriched),'missing_body':sum(not r['body']['complete'] for r in enriched),'actor_labels':len({r['context']['actor'] for r in enriched if r['context'].get('actor')}),'states':dict(Counter(r['review']['state'] for r in enriched))}
    enriched.sort(key=lambda r:(-r['triage']['score'],r['url'],r['observation_id']))
    return enriched,{'summary':summary,'coverage':rows,'comparisons':pairs,'comparison_truncated':truncated,'flows':flows(enriched)}
