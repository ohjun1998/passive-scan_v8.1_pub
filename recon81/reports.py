"""Standalone local reports. No remote scripts, fonts or telemetry."""
import json
from collections import Counter
from pathlib import Path
from .core import private_write


def review_candidates(record):
    text = ' '.join(record['body']['fields']).lower()
    flags = []
    if any(x in text for x in ('userid', 'user_id', 'owner', 'accountid', 'role', 'permission')):
        flags.append('인가 / 객체 소유권 검토')
    if any(x in text for x in ('url', 'redirect', 'callback', 'destination', 'path', 'filename')):
        flags.append('URL / 파일 입력 처리 검토')
    if record['body']['kind'] == 'multipart':
        flags.append('파일 업로드 처리 검토')
    if record['method'] == 'UNKNOWN':
        flags.append('메소드 확인 필요')
    if not record['observed']:
        flags.append('실제 요청 확보 필요')
    return flags


def postman(records):
    items = []
    seen = set()
    for r in records:
        if r['request_id'] in seen:
            continue
        seen.add(r['request_id'])
        request = {'method': r['method'], 'header': r['headers'], 'url': r['url'], 'description': '검토 전용. 민감값은 마스킹되어 있으며 자동 실행이 차단되어 있습니다. 관찰된 요청: ' + str(r['observed'])}
        body = r['body']
        if body['kind'] in ('json', 'form', 'xml', 'text'):
            request['body'] = {'mode': 'raw', 'raw': body['text']}
            if body['kind'] == 'json':
                request['body']['options'] = {'raw': {'language': 'json'}}
        items.append({'name': r['method'] + ' ' + r['url'], 'request': request})
    return {'info': {'name': 'Passive Scan v8.1 — 요청 검토 전용', 'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json', 'description': '자동 재전송 금지. 사용 전 scope·세션·body를 직접 확인하세요.'}, 'event': [{'listen': 'prerequest', 'script': {'type': 'text/javascript', 'exec': ['throw new Error("검토 전용 컬렉션입니다. 요청을 보내려면 복사본에서 이 차단 스크립트를 직접 제거하세요.");']}}], 'item': items}


HTML = r'''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>Passive Scan v8.1 · 요청 인벤토리</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101725;color:#e3eaf7;font:15px system-ui,sans-serif}header{padding:30px 4vw;border-bottom:1px solid #314158}h1{margin:0 0 10px;font-size:26px}p{color:#aebdd3;line-height:1.7}.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{background:#1c2940;padding:14px 20px;border-radius:10px}.stat b{display:block;font-size:26px;color:#8dcbff}.toolbar{display:flex;gap:12px;flex-wrap:wrap;padding:18px 4vw}input,select,button{font:inherit;background:#1c2940;color:#edf3ff;border:1px solid #425570;border-radius:8px;padding:10px}input{min-width:260px;flex:1}main{padding:0 4vw 40px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.tablewrap{max-height:75vh;overflow:auto;border:1px solid #33425b;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th{position:sticky;top:0;background:#24344e}td,th{text-align:left;padding:12px;border-bottom:1px solid #33425b;vertical-align:top}tr[data-index]{cursor:pointer}tr[data-index]:hover,tr.selected{background:#283d5e}td.url{overflow-wrap:anywhere;min-width:170px}.pill{white-space:nowrap;color:#8bdcbb}.static{color:#ffcb83}article{min-width:0;background:#172238;border:1px solid #33425b;border-radius:10px;padding:18px;max-height:75vh;overflow:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1423;border-radius:8px;padding:14px;font:13px/1.6 ui-monospace,monospace}h2{font-size:20px}h3{font-size:15px;color:#91c8ff}.tabs{display:flex;gap:8px;margin-top:20px}.tabs button.active{background:#326593}#detailTitle{overflow-wrap:anywhere}.note{font-size:13px;color:#ffcf94}#visible{font-size:13px;color:#aebdd3}@media(max-width:1050px){.grid{grid-template-columns:1fr}.tablewrap{max-height:42vh}article{max-height:none}}
</style><header><h1>Passive Scan <span style="color:#91c8ff">v8.1</span></h1><p>URL · 메소드 · body · 응답을 함께 확인하는 로컬 요청 인벤토리</p><div class="stats" id="stats"></div><p class="note">실제 트래픽과 정적 추출 결과를 구분합니다. 검토 후보는 취약점 확정 결과가 아닙니다. 패킷은 마스킹·정규화된 내용이며 원본 바이트와 다릅니다.</p></header><div class="toolbar"><input id="search" placeholder="URL, body 필드, body 값 검색"><select id="method"><option value="">모든 메소드</option></select><select id="source"><option value="">모든 출처</option></select><select id="observed"><option value="">모든 관찰 상태</option><option value="true">실제 요청</option><option value="false">정적 추출</option></select></div><main><p id="visible"></p><div class="grid"><div class="tablewrap"><table><thead><tr><th>메소드</th><th>URL</th><th>body 필드</th><th>응답</th><th>출처 / 상태</th></tr></thead><tbody id="rows"></tbody></table></div><article><h2 id="detailTitle">요청을 선택하세요</h2><p id="metadata"></p><p class="note" id="flags"></p><div class="tabs"><button data-tab="request" class="active">요청</button><button data-tab="response">응답</button><button data-tab="json">전체 기록</button></div><pre id="packet"></pre><h3>body 수집 상태</h3><pre id="bodyState"></pre></article></div></main><script id="data" type="application/json">__DATA__</script><script>
'use strict';const records=JSON.parse(document.getElementById('data').textContent);let selected=-1,tab='request';const $=id=>document.getElementById(id);const stat=(label,value)=>{const e=document.createElement('div');e.className='stat';const b=document.createElement('b');b.textContent=value;e.append(b,document.createTextNode(label));$('stats').append(e)};stat('기록',records.length);stat('실제 요청',records.filter(r=>r.observed).length);stat('요청 구조',new Set(records.map(r=>r.structure_id)).size);stat('요청 변형',new Set(records.map(r=>r.request_id)).size);for(const [id,key] of [['method','method'],['source','source']])for(const value of [...new Set(records.map(r=>r[key]))].sort()){const o=document.createElement('option');o.value=value;o.textContent=value;$(id).append(o)}
function render(){const q=$('search').value.toLowerCase();$('rows').replaceChildren();let count=0;records.forEach((r,i)=>{if(($('method').value&&r.method!==$('method').value)||($('source').value&&r.source!==$('source').value)||($('observed').value&&String(r.observed)!==$('observed').value)||!JSON.stringify([r.url,r.body.fields,r.body.text]).toLowerCase().includes(q))return;count++;const tr=document.createElement('tr');tr.dataset.index=i;if(i===selected)tr.className='selected';const values=[r.method,r.url,r.body.fields.join(', ')||'—',r.response?(r.response.status||'응답 대기'):'미수집',r.source+' / '+(r.observed?'실제 요청':'정적 추출')];values.forEach((v,j)=>{const td=document.createElement('td');td.textContent=v;if(j===1)td.className='url';if(j===4)td.className=r.observed?'pill':'static';tr.append(td)});tr.onclick=()=>{selected=i;render();details()};$('rows').append(tr)});$('visible').textContent=count+'개 표시 / '+records.length+'개 기록'}
function details(){if(selected<0)return;const r=records[selected];$('detailTitle').textContent=r.method+' '+r.url;$('metadata').textContent='출처: '+r.source+' · 관찰: '+(r.observed?'실제 요청':'정적 구조')+' · 횟수: '+r.seen_count+' · 시각: '+r.timestamp;$('flags').textContent=(r.review_candidates||[]).join(' · ');const msg=tab==='request'?r: r.response;if(tab==='json')$('packet').textContent=JSON.stringify(r,null,2);else if(!msg)$('packet').textContent='응답이 수집되지 않았습니다.';else{const headline=tab==='request'?r.method+' '+r.url:'HTTP '+msg.status;const headers=msg.headers.map(h=>h.name+': '+h.value).join('\n');$('packet').textContent=headline+'\n'+headers+'\n\n'+(msg.body.text||'['+msg.body.reason+']')}$('bodyState').textContent=JSON.stringify({request:{kind:r.body.kind,complete:r.body.complete,reason:r.body.reason||'',fields:r.body.fields},response:r.response?{kind:r.response.body.kind,complete:r.response.body.complete,reason:r.response.body.reason||''}:null},null,2)}
for(const id of ['search','method','source','observed'])$(id).addEventListener('input',render);for(const b of document.querySelectorAll('[data-tab]'))b.onclick=()=>{tab=b.dataset.tab;document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));details()};render();if(records.length){selected=0;render();details()}
</script></html>'''


def add_excel_sheets(workbook, records):
    from openpyxl.styles import Alignment, Font, PatternFill
    for name, summary in [('Requests v8.1', False), ('Structures v8.1', True)]:
        if name in workbook.sheetnames:
            del workbook[name]
        ws = workbook.create_sheet(name)
        ws.append(['No', 'Method', 'URL', '관찰 상태', 'Body 필드', 'Body 값 (마스킹)', '응답 코드', '출처', '구조 ID', '요청 ID', '검토 후보'])
        seen = set()
        for r in records:
            if summary and r['structure_id'] in seen:
                continue
            seen.add(r['structure_id'])
            def cell(value):
                value = str(value)
                if len(value) > 32000:
                    value = value[:31900] + '\n[Excel 표시 제한: 전체 body는 JSONL/HTML에서 확인]'
                if value.startswith(('=', '+', '-', '@')):
                    value = "'" + value
                # XML 1.0 cell content cannot contain these controls.
                return ''.join(x for x in value if ord(x) >= 32 or x in '\t\n\r')
            ws.append([ws.max_row, r['method'], cell(r['url']), '실제 요청' if r['observed'] else '정적 추출', cell(', '.join(r['body']['fields'])), cell(r['body']['text']), (r.get('response') or {}).get('status', ''), cell(r['source']), r['structure_id'], r['request_id'], cell(', '.join(review_candidates(r)))])
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        for c in ws[1]:
            c.fill = PatternFill('solid', fgColor='193B5B')
            c.font = Font(color='FFFFFF', bold=True)
        widths = [8, 14, 65, 16, 45, 65, 12, 20, 24, 24, 35]
        for i, width in enumerate(widths, 1):
            from openpyxl.utils import get_column_letter
            ws.column_dimensions[get_column_letter(i)].width = width
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.alignment = Alignment(vertical='top', wrap_text=True)


def generate(records, output, xlsx=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    enriched = [dict(r, review_candidates=review_candidates(r)) for r in records]
    private_write(output / 'requests.jsonl', ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in enriched))
    private_write(output / 'postman_review.json', json.dumps(postman(records), ensure_ascii=False, indent=2))
    data = json.dumps(enriched, ensure_ascii=False).replace('<', '\\u003c').replace('&', '\\u0026')
    private_write(output / 'index.html', HTML.replace('__DATA__', data))
    for r in enriched:
        private_write(output / 'evidence' / (r['observation_id'] + '.json'), json.dumps(r, ensure_ascii=False, indent=2))
    if xlsx:
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = 'Summary'
        ws.append(['항목', '개수'])
        ws.append(['전체 기록', len(records)])
        ws.append(['실제 요청', sum(r['observed'] for r in records)])
        ws.append(['정적 추출', sum(not r['observed'] for r in records)])
        for method, count in sorted(Counter(r['method'] for r in records).items()):
            ws.append([method, count])
        ws.column_dimensions['A'].width = 28
        ws.column_dimensions['B'].width = 16
        add_excel_sheets(wb, records)
        target = output / 'request_inventory.xlsx'
        # Reserve privately before openpyxl replaces the content.
        private_write(target, '')
        wb.save(target)
    return len(records)
