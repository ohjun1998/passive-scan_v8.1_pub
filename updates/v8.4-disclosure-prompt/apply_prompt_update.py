"""Apply the reviewed function only to the previously verified v8.4 baseline."""
import argparse
import ast
import hashlib
import os
from pathlib import Path
import tempfile

PACKAGE = Path(__file__).resolve().parent
DOC_NAME = 'PROMPT_DISCLOSURE_REVIEW.md'
DOC_LINK = '\n\n## 정보 노출 AI 검토 프롬프트 개선\n\n[URL 수집부터 최종 산출물까지 전체 흐름 및 변경 기준](PROMPT_DISCLOSURE_REVIEW.md)\n'

def function(source):
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'make_prompt']
    if len(nodes) != 1:
        raise ValueError('make_prompt 함수가 없거나 중복됩니다. 최신 v8.4 원본을 확인하세요.')
    n = nodes[0]
    return n, ''.join(source.splitlines(keepends=True)[n.lineno-1:n.end_lineno])

def signature(node):
    return ast.dump(node, include_attributes=False)

def write_with_backup(path, new, original=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if original is not None:
        if path.is_symlink() or path.read_bytes() != original:
            raise ValueError('파일이 변경되어 적용을 중단합니다: '+str(path))
        backup = path.with_name(path.name+'.before_disclosure_prompt')
        if backup.exists() and backup.read_bytes() != original:
            raise ValueError('다른 백업이 이미 있어 적용을 중단합니다: '+str(backup))
        if not backup.exists():
            with backup.open('xb') as handle:
                handle.write(original)
    elif path.exists():
        raise ValueError('새 파일 경로가 이미 존재합니다: '+str(path))
    fd, tmp = tempfile.mkstemp(prefix='.prompt-update-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as handle:
            handle.write(new)
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def prepare(project):
    target = project/'recon81/codex_review.py'
    if target.is_symlink() or not target.is_file():
        raise ValueError('recon81/codex_review.py가 없습니다. v8.2에는 이 변경을 적용할 수 없습니다.')
    raw = target.read_bytes(); source = raw.decode('utf-8')
    n,_ = function(source)
    old,_ = function((PACKAGE/'verification/previous_make_prompt.py.txt').read_text())
    new,replacement = function((PACKAGE/'make_prompt_replacement.py').read_text())
    if signature(n) == signature(new):
        print('프롬프트는 이미 업데이트되어 있습니다. 문서 상태도 확인합니다.')
        updated = raw
    elif signature(n) == signature(old):
        lines = source.splitlines(keepends=True)
        updated = (''.join(lines[:n.lineno-1])+replacement+''.join(lines[n.end_lineno:])).encode()
        compile(updated,str(target),'exec')
    else:
        raise ValueError('현재 함수가 확인된 이전 원본과 다릅니다. 변경 내용을 먼저 비교하세요. 덮어쓰지 않았습니다.')
    changes=[]
    if updated != raw: changes.append((target,updated,raw))
    doc_target = project/'docs'/DOC_NAME
    doc = (PACKAGE/'docs'/DOC_NAME).read_bytes()
    if doc_target.is_symlink():raise ValueError('문서 심볼릭 링크에는 적용하지 않습니다.')
    if not doc_target.exists():changes.append((doc_target,doc,None))
    elif doc_target.read_bytes() != doc:
        raise ValueError('같은 이름의 다른 문서가 있어 덮어쓰지 않았습니다.')
    for name in ['FLOW.md','USE_CASES.md']:
        p=project/'docs'/name
        if p.is_symlink():raise ValueError('문서 심볼릭 링크에는 적용하지 않습니다.')
        if p.exists():
            before=p.read_bytes()
            if DOC_NAME not in before.decode('utf-8'):
                changes.append((p,before+DOC_LINK.encode(),before))
        else:
            changes.append((p,('# 전체 흐름 및 유스케이스\n'+DOC_LINK).encode(),None))
    return changes

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--apply',action='store_true',help='검사를 통과한 원본에 백업을 만든 뒤 적용')
    args=parser.parse_args()
    try:
        changes=prepare(args.project.resolve())
        for path,after,before in changes:
            print(('적용' if args.apply else '적용 예정')+': '+str(path))
            if args.apply:write_with_backup(path,after,before)
        print('완료' if args.apply else '검사 통과. 실제 반영은 --apply를 지정해야 합니다.')
    except (ValueError,OSError,UnicodeError,SyntaxError) as error:
        parser.exit(2,str(error)+'\n')

if __name__=='__main__':main()
