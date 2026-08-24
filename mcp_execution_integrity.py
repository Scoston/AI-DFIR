#!/usr/bin/env python3
"""MCP 2026-07-28 request/task/cache/root-boundary integrity analysis."""
from __future__ import annotations
import argparse, json, os
from pathlib import Path

TERMINAL={"completed","failed","cancelled","canceled","expired"}

def load(path):
    out=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def inside(path,root):
    try:return os.path.commonpath([os.path.realpath(path),os.path.realpath(root)])==os.path.realpath(root)
    except Exception:return False

def analyze(rows,approved_roots=None):
    roots=list(approved_roots or []);findings=[];tasks={}
    for e in rows:
        method=e.get("mcp_method") or (e.get("headers") or {}).get("Mcp-Method") or e.get("method")
        name=e.get("mcp_name") or (e.get("headers") or {}).get("Mcp-Name") or e.get("tool_name")
        if method=="tools/call" and not name:
            findings.append({"type":"mcp_missing_routing_name","severity":"high","event":e})
        if e.get("issuer_validation_failed"):
            findings.append({"type":"mcp_authorization_issuer_validation_failed","severity":"critical","event":e})
        path=e.get("resolved_path")
        if path and roots and not any(inside(path,r) for r in roots):
            findings.append({"type":"mcp_root_boundary_escape","severity":"critical","resolved_path":path,"event":e})
        if e.get("catalog_type") in ("tools","prompts","resources"):
            if e.get("event")=="cache_read" and e.get("cache_expired"):
                findings.append({"type":"mcp_expired_catalog_cache_read","severity":"high","event":e})
            if e.get("cache_scope")=="shared" and e.get("tenant_id") and e.get("cached_tenant_id") not in (None,e.get("tenant_id")):
                findings.append({"type":"mcp_cross_tenant_catalog_cache","severity":"critical","event":e})
        tid=e.get("task_id")
        if tid:
            t=tasks.setdefault(tid,{"state":None,"cancelled":False,"events":[]})
            t["events"].append(e);state=str(e.get("state") or e.get("status") or "").lower()
            if state:t["state"]=state
            if method in ("tasks/cancel","tasks/update") and state in ("cancelled","canceled"):
                t["cancelled"]=True
            elif t["cancelled"] and method in ("tasks/get","tools/call") and state not in TERMINAL:
                findings.append({"type":"mcp_task_activity_after_cancel","severity":"critical","task_id":tid,"event":e})
    return {"schema":"ai-dfir/mcp-execution-integrity/v1.1","task_count":len(tasks),"findings":findings,"tasks":tasks}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--log",required=True);ap.add_argument("--root",action="append",default=[]);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load(a.log),a.root);text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
