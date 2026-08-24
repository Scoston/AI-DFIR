#!/usr/bin/env python3
"""Read-only case evidence search with SHA-256 hit provenance."""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

TEXT_EXT={'.json','.jsonl','.csv','.md','.txt','.log','.yaml','.yml','.toml','.ini','.py','.sh'}


def sha256_file(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def search(root: Path, query: str, regex=False, case_sensitive=False, max_hits=500):
    flags=0 if case_sensitive else re.I
    rx=re.compile(query,flags) if regex else None
    needle=query if case_sensitive else query.lower();hits=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.suffix.lower() not in TEXT_EXT:continue
        try:
            with p.open(encoding='utf-8',errors='replace') as f:
                for no,line in enumerate(f,1):
                    hay=line if case_sensitive else line.lower()
                    match=bool(rx.search(line)) if rx else needle in hay
                    if match:
                        hits.append({'path':str(p.relative_to(root)),'line':no,'text':line.rstrip()[:1000],
                                     'file_sha256':sha256_file(p)})
                        if len(hits)>=max_hits:return hits
        except Exception:continue
    return hits


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True);ap.add_argument('--query',required=True)
    ap.add_argument('--regex',action='store_true');ap.add_argument('--case-sensitive',action='store_true')
    ap.add_argument('--max-hits',type=int,default=500);ap.add_argument('--out')
    a=ap.parse_args();hits=search(Path(a.case),a.query,a.regex,a.case_sensitive,a.max_hits)
    obj={'schema':'ai-dfir/case-search/v0.7','query':a.query,'hit_count':len(hits),'hits':hits}
    text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)

if __name__=='__main__':main()
