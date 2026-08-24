#!/usr/bin/env python3
"""
Static AI IDE / coding-agent workspace attack-surface inventory.

Covers configuration and trust surfaces highlighted by current public research:
LSP settings, tools/skills, hooks, prompt templates, MCP, IDE settings,
environment prefixing, CI automation, adversarial path names, and local service
configuration. No file is executed.
"""
from __future__ import annotations
import argparse, fnmatch, hashlib, json, os, re, unicodedata
from pathlib import Path

PATTERNS={
 "mcp_config":["**/mcp.json","**/.mcp.json","**/.cursor/mcp.json","**/.roo/mcp.json"],
 "lsp_config":[".vscode/settings.json",".zed/settings.json","settings.json","**/.vscode/settings.json","**/.zed/settings.json","**/settings.json"],
 "prompt_template":["*.prompttemplate",".github/copilot-instructions.md","AGENTS.md","CLAUDE.md",".cursor/rules/**","**/*.prompttemplate","**/.github/copilot-instructions.md","**/AGENTS.md","**/CLAUDE.md","**/.cursor/rules/**"],
 "hooks":[".git/hooks/*",".claude/hooks/**","hooks/**","**/.git/hooks/*","**/.claude/hooks/**","**/hooks/**"],
 "tools_skills":["tools/**","skills/**",".claude/skills/**","**/tools/**","**/skills/**","**/.claude/skills/**"],
 "automation":[".github/workflows/*.yml",".github/workflows/*.yaml","package.json","Makefile","Taskfile*",".devcontainer/**","**/.github/workflows/*.yml","**/.github/workflows/*.yaml","**/package.json","**/Makefile","**/Taskfile*","**/.devcontainer/**"],
 "ide_config":[".vscode/**",".idea/**",".zed/**",".cursor/**",".windsurf/**",".claude/**","**/.vscode/**","**/.idea/**","**/.zed/**","**/.cursor/**","**/.windsurf/**","**/.claude/**"],
}
SENSITIVE_KEYS=("command","executable","path","server","languageServer","mcp","autoApprove","approval","shell","terminal","env","url","endpoint","args")
INSTRUCTION_WORDS=("ignore","follow","read","execute","run","approve","instructions","system","prompt","immediately","secret","token")
BIDI=set(chr(x) for x in [0x202A,0x202B,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069])
ZERO=set(chr(x) for x in [0x200B,0x200C,0x200D,0x2060,0xFEFF])

def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()
def relmatch(rel,pats):return any(fnmatch.fnmatch(rel,p) for p in pats)
def path_findings(rel):
    findings=[]
    lower=rel.lower()
    if any(c in rel for c in BIDI|ZERO):
        findings.append({"type":"workspace_path_invisible_or_bidi_characters","severity":"critical","path":rel})
    base=Path(rel).name.lower()
    hits=sum(1 for w in INSTRUCTION_WORDS if w in base)
    if len(base)>=60 and hits>=2:
        findings.append({"type":"adversarial_instruction_like_path_name","severity":"high","path":rel,"keyword_hits":hits})
    return findings
def inspect_json(path):
    findings=[]
    try:o=json.loads(path.read_text(encoding="utf-8"))
    except Exception:return findings
    text=json.dumps(o,sort_keys=True)
    for key in SENSITIVE_KEYS:
        if re.search(rf'"[^"]*{re.escape(key)}[^"]*"\s*:',text,re.I):
            findings.append({"type":"workspace_sensitive_execution_key","severity":"medium","key":key,"path":str(path)})
    if re.search(r'"[^"]*autoApprove[^"]*"\s*:\s*(?:true|"[^"]+")',text,re.I):
        findings.append({"type":"workspace_autoapproval_setting","severity":"critical","path":str(path)})
    return findings
def inventory(root):
    root=Path(root).resolve();files=[];findings=[]
    for p in root.rglob("*"):
        try:rel=str(p.relative_to(root)).replace("\\","/")
        except Exception:continue
        findings += path_findings(rel)
        if not p.is_file():continue
        cats=[k for k,v in PATTERNS.items() if relmatch(rel,v)]
        if not cats:continue
        item={"path":rel,"sha256":sha(p),"size":p.stat().st_size,"categories":cats}
        files.append(item)
        if p.suffix.lower()==".json":findings += inspect_json(p)
    return {"schema":"ai-dfir/ide-surface-inventory/v1.2","root":str(root),"files":files,"findings":findings}
def diff(a,b):
    aa={x["path"]:x for x in a.get("files",[])};bb={x["path"]:x for x in b.get("files",[])}
    findings=list(b.get("findings") or [])
    for path in sorted(set(bb)-set(aa)):
        sev="critical" if any(c in bb[path]["categories"] for c in ("mcp_config","lsp_config","hooks","tools_skills","automation")) else "high"
        findings.append({"type":"ide_control_surface_added","severity":sev,"file":bb[path]})
    for path in sorted(set(aa)&set(bb)):
        if aa[path]["sha256"]!=bb[path]["sha256"]:
            findings.append({"type":"ide_control_surface_changed","severity":"critical","approved":aa[path],"suspect":bb[path]})
    return {"schema":"ai-dfir/ide-surface-diff/v1.2","approved_root":a.get("root"),"suspect_root":b.get("root"),"findings":findings}
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("inventory");p.add_argument("--root",required=True);p.add_argument("--out")
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    a=ap.parse_args();obj=inventory(a.root) if a.cmd=="inventory" else diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text()))
    s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
