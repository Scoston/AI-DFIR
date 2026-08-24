#!/usr/bin/env python3
"""Offline coding-agent workspace trust inventory and approved-vs-suspect diff."""
from __future__ import annotations
import argparse, fnmatch, hashlib, json, os, stat
from pathlib import Path

PATTERNS=[
 "CLAUDE.md","CLAUDE.local.md","**/CLAUDE.md","AGENTS.md","**/AGENTS.md",
 ".github/copilot-instructions.md",".cursor/rules/**",".mcp.json",
 ".claude/settings.json",".claude/settings.local.json",".claude/rules/**",
 ".vscode/*.json",".devcontainer/**","package.json","Makefile","Taskfile*",
 ".github/workflows/*.yml",".github/workflows/*.yaml",".git/hooks/*"
]
EXEC_PATTERNS=[".git/hooks/*",".github/workflows/*","package.json","Makefile","Taskfile*",".devcontainer/**"]

def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()

def matches(rel,patterns):
    return any(fnmatch.fnmatch(rel,pat) for pat in patterns)

def inventory(root):
    root=Path(root).resolve();files=[]
    for p in sorted(root.rglob("*")):
        try:rel=str(p.relative_to(root)).replace("\\\\","/")
        except Exception:continue
        if not p.is_file() and not p.is_symlink():continue
        if not matches(rel,PATTERNS):continue
        st=os.lstat(p)
        files.append({
          "path":rel,"sha256":None if p.is_symlink() else sha(p),"size":st.st_size,
          "mode":oct(stat.S_IMODE(st.st_mode)),"is_symlink":p.is_symlink(),
          "symlink_target":os.readlink(p) if p.is_symlink() else None,
          "executable":bool(st.st_mode & stat.S_IXUSR),
          "control_type":"executable_or_automation" if matches(rel,EXEC_PATTERNS) else "instruction_or_configuration"
        })
    return {"schema":"ai-dfir/workspace-trust-inventory/v1.1","root":str(root),"files":files}

def diff(a,b):
    aa={x["path"]:x for x in a.get("files",[])};bb={x["path"]:x for x in b.get("files",[])}
    findings=[]
    for rel in sorted(set(bb)-set(aa)):
        x=bb[rel];findings.append({"type":"workspace_control_file_added",
          "severity":"critical" if x["control_type"]=="executable_or_automation" else "high","file":x})
    for rel in sorted(set(aa)&set(bb)):
        if aa[rel]!=bb[rel]:
            findings.append({"type":"workspace_control_file_changed",
              "severity":"critical" if bb[rel]["control_type"]=="executable_or_automation" else "high",
              "path":rel,"approved":aa[rel],"suspect":bb[rel]})
    for rel in sorted(set(aa)-set(bb)):
        findings.append({"type":"workspace_control_file_removed","severity":"medium","path":rel})
    for x in bb.values():
        if x.get("is_symlink"):
            findings.append({"type":"workspace_control_symlink","severity":"high","path":x["path"],"target":x["symlink_target"]})
    return {"schema":"ai-dfir/workspace-trust-diff/v1.1","findings":findings,"approved":a,"suspect":b}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("inventory");p.add_argument("--root",required=True);p.add_argument("--out")
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    a=ap.parse_args()
    obj=inventory(a.root) if a.cmd=="inventory" else diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text()))
    text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
