#!/usr/bin/env python3
"""Effective tool identity and namespace-shadowing analysis."""
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict
from pathlib import Path

def canon(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def identity(t):
    core={"protocol":t.get("protocol"),"server_id":t.get("server_id"),"server_url":t.get("server_url"),
          "cert_fingerprint":t.get("cert_fingerprint"),"tool_name":t.get("tool_name") or t.get("name"),
          "schema_sha256":t.get("schema_sha256"),"version":t.get("version"),
          "authorization_context":t.get("authorization_context")}
    return {**core,"tool_identity_sha256":hashlib.sha256(canon(core)).hexdigest()}

def analyze(inventory,executions=None,approved_ids=None):
    raw=inventory.get("tools",inventory if isinstance(inventory,list) else [])
    tools=[identity(x) for x in raw]
    byname=defaultdict(list);findings=[]
    for t in tools:byname[t["tool_name"]].append(t)
    for name,vals in byname.items():
        ids={x["tool_identity_sha256"] for x in vals}
        if len(ids)>1:
            findings.append({"type":"tool_namespace_shadowing","severity":"critical","tool_name":name,
                             "identities":sorted(ids),"implementations":vals})
    approved=set(approved_ids or (inventory.get("approved_identity_sha256") if isinstance(inventory,dict) else []) or [])
    for e in executions or []:
        tid=e.get("tool_identity_sha256")
        if not tid:
            findings.append({"type":"tool_execution_identity_ambiguous","severity":"high","event":e})
        elif approved and tid not in approved:
            findings.append({"type":"unapproved_tool_identity_executed","severity":"critical","event":e})
    return {"schema":"ai-dfir/tool-identity-analysis/v1.1","tools":tools,"findings":findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--inventory",required=True);ap.add_argument("--executions");ap.add_argument("--out")
    a=ap.parse_args();inv=json.loads(Path(a.inventory).read_text());exe=json.loads(Path(a.executions).read_text()) if a.executions else []
    if isinstance(exe,dict):exe=exe.get("executions",[])
    obj=analyze(inv,exe);text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
