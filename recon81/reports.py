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
        context=r.get('context') or {}
        key=(r['request_id'],context.get('actor',''),context.get('tenant',''))
        if key in seen:
            continue
        seen.add(key)
        request = {'method': r['method'], 'header': r['headers'], 'url': r['url'], 'description': '검토 전용. 민감값은 마스킹되어 있으며 자동 실행이 차단되어 있습니다. 계정: '+context.get('actor','미지정')+' / 조직: '+context.get('tenant','미지정')+' / 관찰된 요청: ' + str(r['observed'])}
        body = r['body']
        if body['kind'] in ('json', 'form', 'xml', 'text'):
            request['body'] = {'mode': 'raw', 'raw': body['text']}
            if body['kind'] == 'json':
                request['body']['options'] = {'raw': {'language': 'json'}}
        items.append({'name': r['method'] + ' ' + r['url'], 'request': request})
    return {'info': {'name': 'Passive Scan v8.2 — 요청 검토 전용', 'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json', 'description': '자동 재전송 금지. 사용 전 scope·세션·body를 직접 확인하세요.'}, 'event': [{'listen': 'prerequest', 'script': {'type': 'text/javascript', 'exec': ['throw new Error("검토 전용 컬렉션입니다. 요청을 보내려면 복사본에서 이 차단 스크립트를 직접 제거하세요.");']}}], 'item': items}


from .dashboard import HTML


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


def add_analysis_sheets(workbook,records,analysis):
    from openpyxl.styles import Font,PatternFill,Alignment
    def cell(value):
        if isinstance(value,(dict,list)): value=json.dumps(value,ensure_ascii=False)
        value=str(value)[:32000]
        value=''.join(c for c in value if ord(c)>=32 or c in '\n\t\r')
        return "'"+value if value.startswith(('=','+','-','@')) else value
    tables={
        'Candidates v8.2':(['Observation ID','Method','URL','Actor','Tenant','Scenario','Priority','Score','Review state','Reasons','Missing','Review note'],[[r['observation_id'],r['method'],r['url'],r['context'].get('actor',''),r['context'].get('tenant',''),r['context'].get('scenario',''),r['triage']['priority'],r['triage']['score'],r['review']['state'],r['triage']['hints'],r['triage']['missing'],r['review'].get('note','')] for r in records]),
        'Coverage v8.2':(['Method','Route','Records','Observed','Actors','States','Missing'],[[r['method'],r['route'],r['records'],r['observed'],r['actors'],r['states'],r['missing']] for r in analysis['coverage']]),
        'Compare v8.2':(['Method','URL','Actor A','Actor B','Evidence A','Evidence B','Comparable','Differences','Reason'],[[p['method'],p['url'],p['left_actor'],p['right_actor'],p['left_id'],p['right_id'],p['comparable'],p['differences'],p['reason']] for p in analysis['comparisons']]),
        'Flows v8.2':(['Actor','Tenant','Scenario','Capture','Steps','Inferred links'],[[f['actor'],f['tenant'],f['scenario'],f['capture_id'],f['steps'],f['links']] for f in analysis['flows']])}
    for name,(header,rows) in tables.items():
        if name in workbook.sheetnames: del workbook[name]
        ws=workbook.create_sheet(name); ws.append(header)
        for row in rows: ws.append([cell(x) for x in row])
        ws.freeze_panes='A2'; ws.auto_filter.ref=ws.dimensions
        for c in ws[1]: c.font=Font(color='FFFFFF'); c.fill=PatternFill('solid',fgColor='193B5B')
        for column in ws.columns: ws.column_dimensions[column[0].column_letter].width=32
        for row in ws.iter_rows(min_row=2):
            for c in row: c.alignment=Alignment(vertical='top',wrap_text=True)


def generate(records, output, xlsx=False, ignore_fields=()):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    from .analysis import analyze
    from .dashboard import HTML as dashboard
    from .core import Scope
    from .network_policy import NetworkPolicy
    from urllib.parse import urlsplit
    from review_queue import build
    enriched,analysis=analyze(records,ignore_fields)
    enriched=[dict(r,review_candidates=review_candidates(r)) for r in enriched]
    private_write(output / 'requests.jsonl', ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in enriched))
    private_write(output / 'postman_review.json', json.dumps(postman(records), ensure_ascii=False, indent=2))
    private_write(output/'analysis.json',json.dumps(analysis,ensure_ascii=False,indent=2))
    hosts={urlsplit(r['url']).hostname for r in records if urlsplit(r['url']).hostname}
    queue=build(records,NetworkPolicy(Scope(hosts))) if hosts else {'schema_version':'8.2','items':[]}
    private_write(output/'review_queue.json',json.dumps(queue,ensure_ascii=False,indent=2))
    data = json.dumps({'records':enriched,'analysis':analysis}, ensure_ascii=False).replace('<', '\\u003c').replace('&', '\\u0026')
    private_write(output / 'index.html', dashboard.replace('__DATA__', data))
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
        add_analysis_sheets(wb,enriched,analysis)
        target = output / 'request_inventory.xlsx'
        # Reserve privately before openpyxl replaces the content.
        private_write(target, '')
        wb.save(target)
    return len(records)
