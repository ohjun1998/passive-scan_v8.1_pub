"""Offline OpenAPI/form discovery. Never resolve external references or invent payloads."""
import json
import math
from html.parser import HTMLParser
from urllib.parse import urljoin
from .core import normalize_record, sanitize_value, safe_url


def clean_metadata(value):
    count=[0]
    def clean(v,depth=0):
        count[0]+=1
        if count[0]>12000 or depth>12: raise ValueError('Metadata complexity limit')
        if isinstance(v,dict): return {str(k)[:128]:clean(x,depth+1) for k,x in v.items()}
        if isinstance(v,list): return [clean(x,depth+1) for x in v[:1000]]
        if isinstance(v,str): return v[:4096]
        if isinstance(v,float) and not math.isfinite(v): raise ValueError('Invalid metadata number')
        if v is None or isinstance(v,(bool,int,float)): return v
        raise ValueError('Unsupported metadata value')
    if not isinstance(value,dict): raise ValueError('Metadata must be an object')
    return sanitize_value(clean(value))


def openapi_records(data,base_url=None):
    if len(data)>8*1024*1024: raise ValueError('Specification exceeds 8 MiB')
    try: doc=json.loads(data)
    except ValueError:
        import yaml
        try: doc=yaml.safe_load(data)
        except yaml.YAMLError: raise ValueError('Invalid specification YAML') from None
    if not isinstance(doc,dict) or not (str(doc.get('openapi','')).startswith('3.') or doc.get('swagger')=='2.0'):
        raise ValueError('Expected OpenAPI 3.x or Swagger 2.0')
    servers=doc.get('servers') or []
    if not base_url:
        if servers: base_url=servers[0].get('url')
        elif doc.get('host'): base_url=(doc.get('schemes') or ['https'])[0]+'://'+doc['host']+doc.get('basePath','')
    if not base_url or not base_url.startswith(('http://','https://')) or '{' in base_url:
        raise ValueError('Provide an absolute concrete --base-url')
    def resolve(obj,seen=()):
        if not isinstance(obj,dict): return {}
        ref=obj.get('$ref')
        if not ref: return obj
        if not isinstance(ref,str) or not ref.startswith('#/') or ref in seen or len(seen)>=10: return {}
        value=doc
        for part in ref[2:].split('/'):
            if not isinstance(value,dict): return {}
            value=value.get(part.replace('~1','/').replace('~0','~'),{})
        return resolve(value,seen+(ref,))
    def fields(schema,path='$',depth=0,seen=()):
        if depth>8 or id(schema) in seen: return []
        schema=resolve(schema)
        result=[]
        for name,child in list((schema.get('properties') or {}).items())[:200]:
            child=resolve(child); field=path+'.'+str(name)
            result.append({'name':field,'type':str(child.get('type','unknown')),'required':name in (schema.get('required') or [])})
            result.extend(fields(child,field,depth+1,seen+(id(schema),)))
        if schema.get('type')=='array': result.extend(fields(schema.get('items',{}),path+'[]',depth+1,seen+(id(schema),)))
        for key in ('allOf','oneOf','anyOf'):
            for child in (schema.get(key) or [])[:20]: result.extend(fields(child,path,depth+1,seen+(id(schema),)))
        return result[:1000]
    for path,path_item in (doc.get('paths') or {}).items():
        if not isinstance(path,str) or not path.startswith('/'): continue
        path_item=resolve(path_item)
        for method,raw in path_item.items():
            if method.lower() not in ('get','head','post','put','patch','delete','options','trace'): continue
            op=resolve(raw); parameters=[]; body_fields=[]; content_types=[]
            for parameter in (path_item.get('parameters') or [])+(op.get('parameters') or []):
                p=resolve(parameter)
                if p.get('in')=='body': body_fields.extend(fields(p.get('schema',{})))
                elif p.get('name'):
                    parameters.append({'name':str(p['name']),'in':str(p.get('in','unknown')),'type':str(resolve(p.get('schema',p)).get('type','unknown')),'required':bool(p.get('required'))})
                    if p.get('in')=='formData': body_fields.append({'name':str(p['name']),'type':str(p.get('type','unknown')),'required':bool(p.get('required'))})
            request_body=resolve(op.get('requestBody',{}))
            for mime,media in (request_body.get('content') or {}).items():
                content_types.append(mime); body_fields.extend(fields(resolve(media).get('schema',{})))
            content_types+=op.get('consumes',doc.get('consumes',[]))
            response_fields=[]
            for response in (op.get('responses') or {}).values():
                response=resolve(response)
                response_fields.extend(fields(response.get('schema',{})))
                for media in (response.get('content') or {}).values(): response_fields.extend(fields(resolve(media).get('schema',{})))
            ct=content_types[0] if content_types else ''
            url=base_url.rstrip('/')+path
            record=normalize_record(url,method,{'Content-Type':ct} if ct else {},source='openapi',observed=False,body_fields=sorted({p['name'] for p in body_fields}),origin_url=base_url)
            record['schema']=clean_metadata({'operation_id':op.get('operationId',''),'path_template':path,'parameters':parameters[:200],'request_fields':body_fields[:1000],'response_fields':response_fields[:1000],'content_types':content_types[:20]})
            yield record


class Forms(HTMLParser):
    def __init__(self): super().__init__(); self.current=None; self.forms=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='form': self.current={'attrs':attrs,'fields':[]}; self.forms.append(self.current)
        elif self.current is not None and tag in ('input','select','textarea') and attrs.get('name'):
            self.current['fields'].append({'name':attrs['name'],'type':attrs.get('type',tag)})
    def handle_endtag(self,tag):
        if tag=='form': self.current=None


def form_records(data,base_url):
    if not base_url: raise ValueError('Forms require --base-url')
    if len(data)>8*1024*1024: raise ValueError('HTML exceeds 8 MiB')
    parser=Forms(); parser.feed(data.decode('utf-8',errors='replace'))
    for form in parser.forms[:1000]:
        attrs=form['attrs']; method=attrs.get('method','GET').upper()
        if method not in ('GET','POST'): continue
        url=urljoin(base_url,attrs.get('action') or base_url)
        if not url.startswith(('http://','https://')): continue
        fs=form['fields'][:200]; ct=attrs.get('enctype','application/x-www-form-urlencoded')
        record=normalize_record(url,method,{'Content-Type':ct} if method=='POST' else {},source='html_form',observed=False,body_fields=[x['name'] for x in fs] if method=='POST' else [],origin_url=base_url)
        record['schema']=clean_metadata({'parameters':[dict(x,**{'in':'query'}) for x in fs] if method=='GET' else [],'request_fields':fs if method=='POST' else [],'content_types':[ct] if method=='POST' else []})
        yield record
