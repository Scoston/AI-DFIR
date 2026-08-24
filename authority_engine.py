#!/usr/bin/env python3
"""
Effective-authority graph and approved-vs-suspect authority diff.

Input JSON:
{
  "principals":[{"id":"agent-A","roles":["role1"],"direct_scopes":["read:tickets"]}],
  "roles":[{"id":"role1","scopes":["read:users"]}],
  "tools":[{"id":"disable_user","requires_scopes":["write:users"],"mutating":true}],
  "delegations":[{"from":"human-1","to":"agent-A","scopes":["write:users"]}],
  "approval_policies":[{"tool":"disable_user","required":true}]
}

Authority is evidence about what actions were reachable, not proof an action occurred.
"""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path

def effective(obj):
    roles={r["id"]:set(r.get("scopes") or []) for r in obj.get("roles",[])}
    principal_scopes=defaultdict(set)
    sources=defaultdict(lambda:defaultdict(list))
    for p in obj.get("principals",[]):
        pid=p["id"]
        for s in p.get("direct_scopes") or []:
            principal_scopes[pid].add(s);sources[pid][s].append("direct")
        for rid in p.get("roles") or []:
            for s in roles.get(rid,set()):
                principal_scopes[pid].add(s);sources[pid][s].append(f"role:{rid}")
    for d in obj.get("delegations",[]):
        to=d.get("to")
        for s in d.get("scopes") or []:
            principal_scopes[to].add(s);sources[to][s].append(f"delegated_by:{d.get('from')}")
    approvals={x["tool"]:x for x in obj.get("approval_policies",[])}
    tools={}
    for t in obj.get("tools",[]):
        req=set(t.get("requires_scopes") or [])
        reachable=[]
        for pid,scopes in principal_scopes.items():
            if req.issubset(scopes):
                reachable.append({
                    "principal":pid,
                    "approval_required":bool((approvals.get(t["id"]) or {}).get("required",False)),
                    "scopes":sorted(scopes),
                })
        tools[t["id"]]={"mutating":bool(t.get("mutating")),"requires_scopes":sorted(req),"reachable_by":reachable}
    return {
        "principals":{p:{"scopes":sorted(s),"sources":{k:v for k,v in sources[p].items()}} for p,s in principal_scopes.items()},
        "tools":tools,
    }

def diff(a,b):
    aa,bb=effective(a),effective(b);findings=[]
    for pid in sorted(set(bb["principals"])|set(aa["principals"])):
        old=set((aa["principals"].get(pid) or {}).get("scopes") or [])
        new=set((bb["principals"].get(pid) or {}).get("scopes") or [])
        added=sorted(new-old)
        if added:
            findings.append({"type":"effective_authority_expanded","severity":"critical",
                             "principal":pid,"added_scopes":added})
    for tid,t in bb["tools"].items():
        old={x["principal"]:x for x in (aa["tools"].get(tid) or {}).get("reachable_by",[])}
        new={x["principal"]:x for x in t.get("reachable_by",[])}
        for pid in sorted(set(new)-set(old)):
            findings.append({"type":"new_tool_reachability","severity":"critical" if t.get("mutating") else "high",
                             "tool":tid,"principal":pid,"mutating":t.get("mutating")})
    return {"schema":"ai-dfir/authority-diff/v0.9","approved":aa,"suspect":bb,"findings":findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("compute");p.add_argument("--input",required=True);p.add_argument("--out")
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    a=ap.parse_args()
    if a.cmd=="compute":obj=effective(json.loads(Path(a.input).read_text()))
    else:obj=diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text()))
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
