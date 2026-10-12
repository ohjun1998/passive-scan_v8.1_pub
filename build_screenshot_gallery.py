#!/usr/bin/env python3
"""Build a local screenshot gallery. Never navigates or re-captures targets."""
import base64
import html
import json
from pathlib import Path
from recon81.core import private_write


def main():
    source=Path('results/screenshots')
    manifest=source/'manifest.json'
    if not manifest.exists(): return
    cards=[]
    for record in json.loads(manifest.read_text()):
        name=record.get('file','')
        if not name or Path(name).name!=name: continue
        image=source/name
        if not image.is_file() or image.stat().st_size>5*1024*1024: continue
        data=base64.b64encode(image.read_bytes()).decode()
        cards.append('<article><p>'+html.escape(record.get('url',''))+'</p><img src="data:image/png;base64,'+data+'"></article>')
    document='<!doctype html><meta charset="utf-8"><title>Screenshot samples</title><style>body{background:#101725;color:#eef;font:15px system-ui;margin:30px}article{margin:20px 0}p{overflow-wrap:anywhere}img{max-width:100%;border:1px solid #456}</style><h1>스크린샷 표본</h1><p>저장된 이미지로 생성한 갤러리입니다. 대상 재접속은 없습니다.</p>'+''.join(cards)
    private_write('reports/screenshot_report/index.html',document)

if __name__=='__main__': main()
