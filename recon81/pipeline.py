"""One offline discovery path for inventory, reports and execution planning.

All in-scope discoveries are retained. Sampling affects the execution plan only;
URLs, errors and reasons are never silently discarded by a report exporter.
"""
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlsplit
from .core import Scope, normalize_record, safe_url, sanitize_value, digest
from .importers import native_record, js_record
from .context import attach_context

ARCHIVE = re.compile(r'^(.*)_(linkfinder|gau|waybackurls|katana|crawl)(?:_[0-9]{2})?\.txt$', re.I)
STATIC_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.eot', '.ttf', '.mp4')
TOOL_NAMES = {'linkfinder': 'LinkFinder', 'jsluice': 'LinkFinder', 'gau': 'GAU', 'waybackurls': 'Waybackurls', 'katana': 'Katana', 'crawl': 'Crawler'}


def make_absolute(url, domain):
    if url.startswith(('http://', 'https://')): return url
    if url.startswith('//'): return 'https:' + url
    return 'https://' + domain + ('/' if not url.startswith('/') else '') + url


def get_safe_domain(target):
    return 'wild_' + target[2:] if target.startswith('*.') else target


def normalize_dynamic_path(path):
    # Only entire strongly identifiable dynamic segments; literal long route names
    # (e.g. /administration) must never be treated as hashes.
    parts=[]
    for part in (path or '/').split('/'):
        if re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', part): part='{UUID}'
        elif re.fullmatch(r'[0-9]{3,}', part): part='{ID}'
        elif re.fullmatch(r'[0-9a-fA-F]{16,}', part) and re.search(r'[0-9]',part) and re.search(r'[a-fA-F]',part): part='{HASH}'
        parts.append(part)
    return '/'.join(parts)


def endpoint_signature(url, method='UNKNOWN'):
    p=urlsplit(safe_url(url))
    return (method.upper(), p.scheme, p.netloc, normalize_dynamic_path(p.path), tuple(sorted(k for k,_ in parse_qsl(p.query,keep_blank_values=True))))


def _error(stats, path, line, reason):
    stats['parse_errors']+=1
    if len(stats['errors'])<100:
        # Do not include the source line or exception text; either may hold secrets.
        stats['errors'].append({'file':Path(path).name,'line':line,'reason':reason})


def _lines(path, stats):
    try:
        with Path(path).open(encoding='utf-8-sig') as stream:
            for number,line in enumerate(stream,1):
                if line.strip() and not line.lstrip().startswith('#'):
                    yield number,line.strip()
    except (OSError,UnicodeError):
        _error(stats,path,0,'unreadable_input')


def mappings(results, stats):
    values={}
    for path in sorted(Path(results).rglob('*_js_mapping.txt')):
        for number,line in _lines(path,stats):
            if '\t' not in line:
                _error(stats,path,number,'invalid_js_mapping'); continue
            name,url=line.split('\t',1)
            try: values[name]=safe_url(url)
            except ValueError: _error(stats,path,number,'invalid_js_mapping_url')
    return values


def _receipt(record, path, number, line, root):
    # Identity of this saved source event, independent of checkout location. Raw
    # lines (which may contain secrets) are never written to the receipt table.
    record['_ingest_receipt'] = digest([str(path.relative_to(root)), number, hashlib.sha256(line.encode()).hexdigest()])
    return record


def saved_records(results, scope, stats):
    """Yield sanitized canonical records from saved tool outputs, line by line."""
    results=Path(results)
    mapping=mappings(results,stats)
    known_js=set()
    for path in sorted(results.rglob('*_js_requests_*.jsonl')):
        for number,line in _lines(path,stats):
            try:
                item=json.loads(line)
                record=native_record(item) if 'schema_version' in item else js_record(item,item.get('origin_url'))
                if scope.allows(record['url']):
                    known_js.add(record['url']); yield _receipt(record,path,number,line,results)
                else: stats['out_of_scope']+=1
            except (ValueError,KeyError,TypeError,AttributeError,RecursionError): _error(stats,path,number,'invalid_request_record')
    target_map={get_safe_domain(t):t for t in scope.patterns}
    for path in sorted(results.rglob('*.txt')):
        match=ARCHIVE.match(path.name)
        if not match: continue
        target=target_map.get(match[1].lower())
        if not target: continue
        base=target[2:] if target.startswith('*.') else target
        source=match[2].lower()
        for number,line in _lines(path,stats):
            origin,raw=line.split('\t',1) if '\t' in line else (None,line)
            try:
                absolute=make_absolute(raw,base)
                if not scope.allows(absolute): stats['out_of_scope']+=1; continue
                url=safe_url(absolute)
                # LinkFinder text is a compatibility projection of the richer JS
                # record, not an independent UNKNOWN-method observation.
                if source=='linkfinder' and url in known_js: continue
                origin_url=mapping.get(origin)
                if not origin_url and origin and origin.startswith(('http://','https://')): origin_url=origin
                yield _receipt(normalize_record(url,'UNKNOWN',source=source,observed=False,origin_url=origin_url),path,number,line,results)
            except (ValueError,TypeError): _error(stats,path,number,'invalid_archive_url')
    for path in sorted(results.rglob('httpx_results_*.json')):
        if path.name.endswith('.network.json'):
            continue  # Transport ledgers are not the tool's target-response JSONL.
        for number,line in _lines(path,stats):
            try:
                item=json.loads(line); url=item.get('url') or item.get('input')
                if not url or not scope.allows(url): stats['out_of_scope']+=1; continue
                headers=item.get('header') or item.get('headers') or item.get('response_headers') or {}
                if not isinstance(headers,dict): headers={}
                r=normalize_record(url,'GET',body=b'',response={'status':item.get('status_code',0),'headers':headers,'body':None},source='httpx',timestamp=item.get('timestamp'))
                r['probe']=sanitize_value({'server':str(item.get('webserver') or '-'),'tech':[str(t) for t in item.get('tech',[])] if isinstance(item.get('tech'),list) else []})
                attach_context(r,r.get('context'))
                yield _receipt(r,path,number,line,results)
            except (ValueError,KeyError,TypeError,AttributeError): _error(stats,path,number,'invalid_probe_record')
    for path in sorted(results.rglob('httpx_results_*.deferred.txt')):
        for number,line in _lines(path,stats):
            try:
                if scope.allows(line): yield _receipt(normalize_record(line,'UNKNOWN',source='httpx_deferred',observed=False),path,number,line,results)
                else: stats['out_of_scope']+=1
            except (ValueError,TypeError): _error(stats,path,number,'invalid_deferred_url')


def ingest_saved(results, scope, inventory, history_files=()):
    """Idempotently store every discovery; an exporter never determines retention."""
    stats={'schema_version':'8.6','imported':0,'unchanged':0,'out_of_scope':0,'parse_errors':0,'errors':[]}
    inventory.conn.execute('CREATE TABLE IF NOT EXISTS pipeline_receipts (receipt TEXT PRIMARY KEY, observation_id TEXT NOT NULL)')
    def add(record):
        receipt=record.pop('_ingest_receipt',None)
        already_seen=receipt and inventory.conn.execute('SELECT 1 FROM pipeline_receipts WHERE receipt=?',(receipt,)).fetchone()
        existing=inventory.conn.execute('SELECT 1 FROM observations WHERE id=?',(record['observation_id'],)).fetchone()
        # Re-exporting unchanged files is idempotent; distinct saved captures
        # still append chronology even when their request/response is identical.
        if already_seen or (existing and not record['observed']): stats['unchanged']+=1
        else: inventory.add(record); stats['imported']+=1
        if receipt:
            inventory.conn.execute('INSERT OR IGNORE INTO pipeline_receipts VALUES (?,?)',(receipt,record['observation_id']))
    for record in saved_records(results,scope,stats): add(record)
    existing_urls={r['url'] for r in inventory.records()}
    for path in history_files:
        if not Path(path).is_file(): continue
        for number,line in _lines(path,stats):
            try:
                if not scope.allows(line): stats['out_of_scope']+=1; continue
                url=safe_url(line)
                if url not in existing_urls:
                    add(normalize_record(url,'UNKNOWN',source='legacy_history',observed=False)); existing_urls.add(url)
            except (ValueError,TypeError): _error(stats,path,number,'invalid_history_url')
    inventory.conn.commit()
    stats['partial']=stats['parse_errors']>0
    return stats


def execution_plan(records, policy, samples_per_signature=5):
    """Deterministic queue; full source inventory remains untouched."""
    if samples_per_signature<1: raise ValueError('samples_per_signature must be positive')
    by_url=defaultdict(list)
    for record in records: by_url[record['url']].append(record)
    ordered=sorted(by_url,key=lambda url:(hashlib.sha256(url.encode()).hexdigest(),url))
    selected=[]; deferred=[]; counts=Counter()
    for url in ordered:
        variants=by_url[url]
        methods={r['method'] for r in variants}
        method='GET' if 'GET' in methods else sorted(methods-{'UNKNOWN'})[0] if methods-{'UNKNOWN'} else 'UNKNOWN'
        reason=None
        if method not in ('GET','UNKNOWN'): reason='method_not_baseline_get'
        if not reason: reason=policy.reason(url,'GET' if method=='UNKNOWN' else method)
        if not reason and urlsplit(url).path.lower().endswith(STATIC_EXTENSIONS): reason='static_asset'
        key=endpoint_signature(url,method)
        if not reason and counts[key]>=samples_per_signature: reason='signature_sample_limit'
        if reason: deferred.append({'url':url,'method':method,'reason':reason,'observation_ids':sorted(r['observation_id'] for r in variants)})
        else: selected.append(url); counts[key]+=1
    return selected,deferred,{'schema_version':'8.6','total_urls':len(by_url),'selected':len(selected),'deferred':len(deferred),'deferred_by_reason':dict(Counter(r['reason'] for r in deferred)),'samples_per_signature':samples_per_signature,'order':'sha256(url), url','inventory_preserved':True}


def url_projection(records, targets):
    """Rich legacy sheets group canonical observations by URL, never sample them."""
    matrix={t:{} for t in targets}
    scopes={t:Scope([t]) for t in targets}
    for r in records:
        for target,scope in scopes.items():
            if not scope.allows(r['url']): continue
            data=matrix[target].setdefault(r['url'],{'tools':set(),'files':set(),'methods':set(),'observation_ids':set(),'is_new':False})
            data['tools'].add(TOOL_NAMES.get(r['source'].lower(),r['source']))
            if r.get('origin_url'): data['files'].add(r['origin_url'])
            data['methods'].add(r['method']); data['observation_ids'].add(r['observation_id'])
    return matrix


def function_category(url):
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    path = parsed.path
    query = parsed.query

    # 1순위: 관리자/내부망(Admin/internal) - 국내 실정(bo, cms) 및 인프라 반영
    if any(kw in path for kw in ['/admin', '/internal', '/manage', '/bo', '/backoffice', '/cms', '/system', '/dashboard', '/console', '/debug', '/test', '/api-docs', '/swagger']):
        return "🛠️ 관리자/내부(Admin)"
        
    # 2순위: 인증(Auth) - 최신 인증(토큰, MFA) 방식 반영
    if any(kw in path or kw in query for kw in ['login', 'register', 'reset-password', 'verify', 'oauth', 'sso', 'session', 'signin', 'signup', 'auth', 'token', 'mfa', 'otp', '2fa', 'password', 'pwd', 'recover', 'saml']):
        return "🔑 인증(Auth)"
        
    # 3순위: 자금/결제(Money) - 포인트, 마일리지 등 비즈니스 로직 취약점 타겟 반영
    if any(kw in path or kw in query for kw in ['transfer', 'checkout', 'refund', 'coupon', 'invoice', 'withdraw', 'payment', 'pay', 'billing', 'point', 'mileage', 'cart', 'wallet', 'balance', 'transaction']):
        return "💸 자금/결제(Money)"
        
    # 4순위: 파일 처리(File handling) - LFI/SSRF 유발 경로 반영
    if any(kw in path or kw in query for kw in ['upload', 'download', 'export', 'import', 'avatar', 'file', 'attachment', 'document', 'pdf', 'csv', 'excel', 'report', 'load', 'read']):
        return "📁 파일 처리(File)"
        
    # 5순위: 객체 접근(Object access) - 국내 개발 문화(idx, seq, no) 반영
    query_dict = dict(parse_qsl(query, keep_blank_values=True))
    query_keys = [k.lower() for k in query_dict.keys()]
    if any(kw in key for key in query_keys for kw in ['id', 'no', 'num', 'seq', 'idx', 'key', 'uuid']):
        return "📦 객체 접근(Object)"
        
    return "기타(Others)"

def get_function_priority(cat):
    if cat == "🛠️ 관리자/내부(Admin)": return 1
    if cat == "💸 자금/결제(Money)": return 2
    if cat == "🔑 인증(Auth)": return 3
    if cat == "📁 파일 처리(File)": return 4
    if cat == "📦 객체 접근(Object)": return 5
    return 6
