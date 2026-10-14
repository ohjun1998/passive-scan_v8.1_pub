"""Coverage snapshots, explicit test labels and readable offline PDF reports."""
import hashlib
import html
import json
import os
import tempfile
from pathlib import Path
from .core import private_write,sanitize_value
from .ai_review import _json,_publish,load_json,read_bytes,validate_result,verify_packet,ASSESSMENTS,CONFIDENCE
from .review_batch import refresh,serialized


@serialized
def batch_report(directory,output):
    coverage=refresh(directory);aggregate=load_json(Path(directory)/'aggregate.json',16*1024*1024)
    lines=['# 저장 증거 AI 검토 보고서','', '인용 일치는 위치·발췌 확인이며 취약점 확정·재현 검증이 아닙니다.', '',
        '배치 ID: '+aggregate['batch_id'],'',
        f"완료 묶음 {coverage['summary']['completed_packets']} / 전체 {coverage['summary']['packets']}",
        '진단 상태: '+json.dumps(coverage['summary']['stages'],ensure_ascii=False),'']
    for i,review in enumerate(aggregate['reviews'],1):
        draft=review['report_draft']
        lines+=['## '+str(i)+'. '+draft['title'],'',ASSESSMENTS[review['assessment']]+' / '+CONFIDENCE[review['confidence']],review['reason'],'',
                '증거: '+', '.join(review['observation_ids'])]
        for cite in review['citations']:lines.append('근거: '+cite['location']+' '+cite['pointer']+' = '+cite['excerpt'])
        for label,key in [('영향','impact'),('기대','expected'),('관찰','actual'),('개선','remediation')]:lines.append(label+': '+draft[key])
        lines+=['추가 확인:']+['- '+x for x in review['next_checks']]+['']
    text='\n'.join(lines)+'\n'
    page='<!doctype html><html lang="ko"><meta charset="utf-8"><title>AI 검토</title><style>body{max-width:1100px;margin:32px auto;padding:16px;font:16px/1.7 sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>저장 증거 AI 검토</h1><pre>'+html.escape(text)+'</pre></html>'
    return _publish(output,{'aggregate.json':_json(aggregate),'coverage.json':_json(coverage),'review.md':text,'index.html':page,
        'execution.json':_json({'provider':'batch_aggregate','human_confirmation_required':True,'target_requests_sent':0,
            'model_execution_verified':False,'notice':'Per-packet execution receipts are authoritative; aggregate does not attest all model executions.'})})


def _read_report(directory):
    directory=Path(directory);manifest=load_json(directory/'manifest.json')
    for name,expected in manifest.get('files',{}).items():
        path=Path(name)
        if path.is_absolute() or '..' in path.parts:raise ValueError('Invalid report receipt path')
        if hashlib.sha256(read_bytes(directory/path,16*1024*1024)).hexdigest()!=expected:raise ValueError('Report file changed')
    if (directory/'aggregate.json').exists():
        result=load_json(directory/'aggregate.json',16*1024*1024)
        return result['reviews'],result.get('coverage',{}),load_json(directory/'execution.json')
    packet=verify_packet(load_json(directory/'packet.json',2*1024*1024))
    result=validate_result(load_json(directory/'ai_review.json'),packet)
    return result['reviews'],{'summary':{'records':len(packet['evidence'])},'packet_id':packet['packet_id']},load_json(directory/'execution.json')


def evaluate(directory,labels_path,output):
    reviews,coverage,execution=_read_report(directory);labels=load_json(labels_path)
    if set(labels)!={'cases','provenance'} or not isinstance(labels['cases'],list) or not labels['provenance']:
        raise ValueError('Evaluation labels require explicit provenance')
    if not 1<=len(labels['cases'])<=1000:raise ValueError('Evaluation label limit')
    cases=[];case_ids=set();counts={'true_positive':0,'false_positive':0,'false_negative':0,'true_negative':0,'abstained_or_unreviewed':0}
    if coverage.get('records') is not None:allowed={r['observation_id'] for r in coverage['records']}
    else:
        packet=load_json(Path(directory)/'packet.json',2*1024*1024);allowed={r['observation_id'] for r in packet['evidence']}
    for case in labels['cases']:
        if set(case)!={'case_id','observation_ids','expected_assessment','category'} or case['case_id'] in case_ids:
            raise ValueError('Invalid or duplicate evaluation case')
        case_ids.add(case['case_id'])
        expected=case['expected_assessment']
        if expected not in ('suspicious','likely_benign','insufficient_evidence') or not case['observation_ids'] or not set(case['observation_ids'])<=allowed:
            raise ValueError('Evaluation case evidence is outside the report')
        predictions={r['assessment'] for r in reviews if set(r['observation_ids'])&set(case['observation_ids'])}
        predicted='suspicious' if 'suspicious' in predictions else 'likely_benign' if 'likely_benign' in predictions else 'insufficient_evidence'
        category='abstained_or_unreviewed'
        if predicted!='insufficient_evidence' and expected!='insufficient_evidence':
            category='true_positive' if expected==predicted=='suspicious' else 'true_negative' if expected==predicted=='likely_benign' else 'false_positive' if predicted=='suspicious' else 'false_negative'
        counts[category]+=1
        cases.append(dict(case,predicted_assessment=predicted,prediction_conflict=len(predictions)>1,outcome=category))
    positives=sum(c['expected_assessment']=='suspicious' for c in cases)
    tp=counts['true_positive'];fp=counts['false_positive']
    metrics=dict(counts,precision=tp/(tp+fp) if tp+fp else None,recall=tp/positives if positives else None,
                 labeled_cases=len(cases),expected_positives=positives)
    result={'schema_version':'8.5','label_provenance':sanitize_value(labels['provenance']),'metrics':metrics,'cases':cases,
            'notice':'Metrics apply only to these user-declared labels. Citation correctness is not semantic correctness or general detection quality.'}
    _publish(output,{'evaluation.json':_json(result)})
    return result


def find_font(explicit=None):
    if explicit:
        path=Path(explicit)
        if path.is_symlink() or not path.is_file():raise ValueError('Expected a regular font file')
        return path
    paths=['/usr/share/fonts/truetype/nanum/NanumGothic.ttf','/usr/local/share/fonts/truetype/nanum/NanumGothic-Regular.ttf',
           '/System/Library/Fonts/Supplemental/AppleGothic.ttf','C:/Windows/Fonts/malgun.ttf']
    for value in paths:
        if Path(value).is_file():return Path(value)
    raise ValueError('Korean font not found; use --font with a Korean TTF font')


def export_pdf(directory,output,font=None,max_reviews=200):
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.colors import HexColor,white
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if not 1<=max_reviews<=500:raise ValueError('PDF review limit')
    reviews,coverage,execution=_read_report(directory);output=Path(output)
    if output.exists() or output.is_symlink():raise ValueError('PDF output already exists')
    font_path=find_font(font);pdfmetrics.registerFont(TTFont('ReviewKR',str(font_path)))
    styles={k:ParagraphStyle(k,fontName='ReviewKR',fontSize=size,leading=leading,wordWrap='CJK',spaceAfter=8,textColor=HexColor('#243A4D'))
            for k,size,leading in [('title',21,29),('heading',13,20),('body',10,16),('small',8.5,13)]}
    def p(text,style='body'):return Paragraph(html.escape(str(text)).replace('\n','<br/>'),styles[style])
    story=[p('저장 증거 AI 검토 보고서','title'),p('Passive Scan v8.5 · 관찰 사실·AI 의견·재현 확인을 구분합니다.'),
        p('AI 의견은 취약점 확정 또는 최종 제출 승인이 아닙니다. 인용 검증은 실제 위치·발췌의 일치만 확인합니다.')]
    summary=coverage.get('summary',{})
    rows=[['항목','결과'],['검토 의견',len(reviews)],['선택 증거',summary.get('records','미기록')],
          ['진단 상태',' · '.join({'discovered':'URL 발견','captured':'실제 응답 확보','partially_reviewed':'일부 검토','ai_reviewed':'AI 검토 연결','evidence_validated':'인용 일치 확인'}.get(k,k)+' '+str(v) for k,v in summary.get('stages',{}).items())],['실행 경로',execution.get('provider','미기록')],
          ['실제 모델 실행 확인','확인됨' if execution.get('model_execution_verified') else '미확인'],
          ['Pro 등급 확인','확인됨' if execution.get('subscription_plan_verified') else '미확인'],['사람 최종 확인','필요'],
          ['PDF에서 생략한 의견',max(0,len(reviews)-max_reviews)]]
    table=Table([[p(a),p(b)] for a,b in rows],colWidths=[135,372],repeatRows=1,hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),HexColor('#E7F0F7')),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LINEBELOW',(0,0),(-1,-1),.4,HexColor('#D5DFE7'))]))
    story+=[table,Spacer(1,15),p('기본 처리 흐름','heading'),p('URL·캡처 수집 → 범위·마스킹·인벤토리 → 자원별 증거 분할 → 신원·정책 근거 연결 → AI 검토 → 인용 검증 → 커버리지·평가 → 보고서 → 진단자 최종 확인'),
        p('배치 보고서의 모델 실행 확인은 각 묶음의 execution.json에서 확인합니다. 전체 집계는 모든 묶음의 모델 실행을 보증하지 않습니다.','small')]
    assessments={'suspicious':'의심 항목','likely_benign':'정상 동작 가능성','insufficient_evidence':'증거 부족'}
    for i,review in enumerate(reviews[:max_reviews],1):
        draft=review['report_draft'];story+=[PageBreak(),p(str(i)+'. '+draft['title'],'title'),
            p(assessments.get(review['assessment'],review['assessment'])+' · 신뢰도 '+CONFIDENCE[review['confidence']],'heading'),p(review['reason']),
            p('증거 ID','heading'),p('\n'.join(review['observation_ids']),'small'),p('검증한 인용','heading')]
        for cite in review.get('citations',[]):story.append(p(cite['location']+' '+cite['pointer']+'\n'+cite['excerpt'],'small'))
        if not review.get('citations'):story.append(p('구형 결과 또는 인용 없는 증거 부족 의견. 위치·발췌는 검증되지 않았습니다.','small'))
        for title,key in [('관찰 결과','actual'),('기대 동작','expected'),('영향','impact'),('개선안','remediation')]:
            story.extend([p(title,'heading'),p(draft[key])])
        story.extend([p('관찰·재현 초안','heading')]+[p('• '+x) for x in draft['steps']])
        story.extend([p('추가 확인 계획','heading')]+[p('• '+x) for x in review['next_checks']])
    def footer(canvas,doc):
        canvas.setFont('ReviewKR',8);canvas.setFillColor(HexColor('#657787'))
        canvas.drawString(44,28,'PASSIVE SCAN v8.5 | 저장 증거 AI 검토');canvas.drawRightString(A4[0]-44,28,str(doc.page))
    output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(prefix='.review-pdf-',suffix='.pdf',dir=output.parent);os.close(fd)
    temporary=Path(name)
    try:
        SimpleDocTemplate(str(temporary),pagesize=A4,leftMargin=44,rightMargin=44,topMargin=44,bottomMargin=50,
                          title='저장 증거 AI 검토 보고서').build(story,onFirstPage=footer,onLaterPages=footer)
        # Exclusive create avoids overwriting a concurrently-created PDF.
        with output.open('xb') as stream:stream.write(temporary.read_bytes())
        output.chmod(0o600)
    finally:temporary.unlink(missing_ok=True)
    return output
