#!/usr/bin/env python3
"""Read-only local evidence acquisition for coding/desktop agents.

The collector copies explicitly modeled files into a case acquisition directory
without executing project content. Missing paths are recorded as gaps.
"""
from __future__ import annotations
import argparse,fnmatch,hashlib,json,os,shutil
from pathlib import Path

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()
CLAUDE_PATTERNS=[
 '.claude/history.jsonl','.claude.json','.claude/CLAUDE.md','.claude/settings.json',
 '.claude/projects/**/*.jsonl','.claude/projects/**/tool-results/**','.claude/file-history/**',
 '.claude/session-env/**','.claude/shell-snapshots/**'
]
PROJECT_PATTERNS=['CLAUDE.md','AGENTS.md','.mcp.json','.claude/CLAUDE.md','.claude/settings.json','.claude/settings.local.json','.github/copilot-instructions.md','.cursor/rules/**','.cursor/mcp.json','.vscode/settings.json']
CURSOR_PATTERNS=['.cursor/**']

def match(rel,patterns):return any(fnmatch.fnmatch(rel,p) for p in patterns)
def collect(home,project,out,agent='claude_code'):
    home=Path(home).expanduser().resolve();project=Path(project).resolve() if project else None;out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    sources=[];gaps=[]
    roots=[('home',home,CLAUDE_PATTERNS if agent=='claude_code' else CURSOR_PATTERNS)]
    if project:roots.append(('project',project,PROJECT_PATTERNS))
    seen=set()
    for label,root,patterns in roots:
        if not root.exists():gaps.append({'root':str(root),'reason':'root_missing'});continue
        for p in root.rglob('*'):
            if not p.is_file() or p.is_symlink():continue
            rel=str(p.relative_to(root)).replace('\\','/')
            logical=(('.claude/'+rel) if label=='home' and root.name!='.claude' and rel.startswith('.claude/') is False and agent=='claude_code' else rel)
            # For home root, patterns are relative to the user's home.
            relmatch=rel
            if not match(relmatch,patterns):continue
            key=(str(p),sha(p))
            if key in seen:continue
            seen.add(key);dest=out/label/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
            sources.append({'source_path':str(p),'captured_path':str(dest),'sha256':key[1],'size_bytes':p.stat().st_size,'root':label})
    return {'schema':'ai-dfir/local-agent-acquisition/v1.5','agent':agent,'sources':sources,'gaps':gaps,'count':len(sources),'rule':'Read-only copy; no project file is executed.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--home',default=str(Path.home()));ap.add_argument('--project');ap.add_argument('--out',required=True);ap.add_argument('--agent',choices=['claude_code','cursor'],default='claude_code');ap.add_argument('--manifest')
    a=ap.parse_args();obj=collect(a.home,a.project,a.out,a.agent);txt=json.dumps(obj,indent=2,sort_keys=True);Path(a.manifest).write_text(txt) if a.manifest else print(txt)
if __name__=='__main__':main()
