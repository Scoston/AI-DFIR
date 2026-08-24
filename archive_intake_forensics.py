#!/usr/bin/env python3
"""
Static archive/package intake forensics.

Lists ZIP/TAR metadata without extracting member content. Detects path traversal,
absolute paths, symlinks, extreme compression ratios, nested archives, and
workspace/agent control files that could be auto-loaded after extraction.

No archive member is executed.
"""
from __future__ import annotations
import argparse, json, os, posixpath, stat, tarfile, zipfile
from pathlib import Path

CONTROL_NAMES=(
 "CLAUDE.md","CLAUDE.local.md","AGENTS.md",".mcp.json","package.json","Makefile",
 ".github/copilot-instructions.md"
)
CONTROL_PARTS=(".cursor/","/.cursor/","/.claude/","/.vscode/","/.devcontainer/",
               ".github/workflows/","/.git/hooks/","/skills/","/tools/")

def suspicious_name(name):
    clean=name.replace("\\","/")
    norm=posixpath.normpath(clean)
    absolute=clean.startswith("/") or (len(clean)>2 and clean[1]==":" and clean[2] in "/\\")
    traversal=norm==".." or norm.startswith("../") or "/../" in "/"+norm
    control=Path(clean).name in CONTROL_NAMES or any(x in clean for x in CONTROL_PARTS)
    nested=clean.lower().endswith((".zip",".tar",".tgz",".gz",".7z",".rar",".jar",".whl",".vsix"))
    return absolute,traversal,control,nested

def analyze_zip(path):
    findings=[];members=[]
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            absolute,traversal,control,nested=suspicious_name(i.filename)
            mode=(i.external_attr>>16)&0xFFFF
            symlink=stat.S_ISLNK(mode)
            ratio=(i.file_size/max(1,i.compress_size)) if i.file_size else 1.0
            row={"name":i.filename,"size":i.file_size,"compressed_size":i.compress_size,
                 "compression_ratio":round(ratio,2),"is_symlink":symlink,
                 "control_surface":control,"nested_archive":nested}
            members.append(row)
            if absolute or traversal:
                findings.append({"type":"archive_path_escape","severity":"critical","member":row})
            if symlink:
                findings.append({"type":"archive_symlink_member","severity":"high","member":row})
            if ratio>=100 and i.file_size>=1024*1024:
                findings.append({"type":"archive_extreme_compression_ratio","severity":"high","member":row})
            if control:
                findings.append({"type":"archive_contains_agent_autoload_control","severity":"high","member":row})
            if nested:
                findings.append({"type":"archive_contains_nested_archive","severity":"medium","member":row})
    return members,findings

def analyze_tar(path):
    findings=[];members=[]
    with tarfile.open(path,"r:*") as t:
        for i in t.getmembers():
            absolute,traversal,control,nested=suspicious_name(i.name)
            row={"name":i.name,"size":i.size,"is_symlink":i.issym() or i.islnk(),
                 "linkname":i.linkname if (i.issym() or i.islnk()) else None,
                 "control_surface":control,"nested_archive":nested}
            members.append(row)
            if absolute or traversal:
                findings.append({"type":"archive_path_escape","severity":"critical","member":row})
            if row["is_symlink"]:
                findings.append({"type":"archive_symlink_member","severity":"high","member":row})
            if control:
                findings.append({"type":"archive_contains_agent_autoload_control","severity":"high","member":row})
            if nested:
                findings.append({"type":"archive_contains_nested_archive","severity":"medium","member":row})
    return members,findings

def analyze(path):
    p=Path(path);lower=p.name.lower()
    if zipfile.is_zipfile(p):members,findings=analyze_zip(p)
    elif tarfile.is_tarfile(p):members,findings=analyze_tar(p)
    else:raise ValueError("not a supported ZIP/TAR archive")
    return {"schema":"ai-dfir/archive-intake-analysis/v1.2","path":str(p.resolve()),
            "member_count":len(members),"members":members[:5000],"findings":findings,
            "rule":"Static metadata analysis only; archive members are not extracted or executed."}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(a.path);s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
