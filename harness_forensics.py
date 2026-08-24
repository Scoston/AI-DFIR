#!/usr/bin/env python3
"""Agent harness inventory, configuration diff, and lifecycle analysis."""
from __future__ import annotations
import argparse, hashlib, json
from collections import Counter
from pathlib import Path

FIELDS={
 "package":"critical","version":"high","binary_sha256":"critical","container_digest":"critical",
 "prompt_assembly_sha256":"critical","middleware_sha256":"critical","hooks_sha256":"critical",
 "tool_policy_sha256":"critical","approval_policy_sha256":"critical","memory_strategy_sha256":"high",
 "stop_policy_sha256":"critical","context_priority_sha256":"critical","dynamic_imports_sha256":"critical",
 "plugin_registry_sha256":"critical","skill_registry_sha256":"critical",
}

def canon(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def digest(o):return hashlib.sha256(canon(o)).hexdigest()

def normalize(obj):
    def h(x):return digest(x or {})
    return {
      "harness_id":obj.get("harness_id") or obj.get("name"),
      "package":obj.get("package"),"version":obj.get("version"),
      "binary_sha256":obj.get("binary_sha256"),"container_digest":obj.get("container_digest"),
      "prompt_assembly_sha256":h(obj.get("prompt_assembly")),
      "middleware_sha256":h(obj.get("middleware")),
      "hooks_sha256":h(obj.get("hooks")),
      "tool_policy_sha256":h(obj.get("tool_policy")),
      "approval_policy_sha256":h(obj.get("approval_policy")),
      "memory_strategy_sha256":h(obj.get("memory_strategy")),
      "stop_policy_sha256":h(obj.get("stop_policy")),
      "context_priority_sha256":h(obj.get("context_priority")),
      "dynamic_imports_sha256":h(sorted(obj.get("dynamic_imports") or [])),
      "plugin_registry_sha256":h(obj.get("plugins")),
      "skill_registry_sha256":h(obj.get("skills")),
      "raw":obj,
    }

def diff(approved,suspect):
    a,b=normalize(approved),normalize(suspect);findings=[]
    for field,sev in FIELDS.items():
        if a.get(field)!=b.get(field):
            findings.append({"type":f"harness_{field}_changed","severity":sev,
                             "approved":a.get(field),"suspect":b.get(field)})
    # Explicit additions are useful to analysts even when the aggregate hash already changed.
    for key,label in [("dynamic_imports","dynamic_import"),("plugins","plugin"),("skills","skill")]:
        av=approved.get(key) or [];bv=suspect.get(key) or []
        def ids(vals):
            out=set()
            for x in vals:
                if isinstance(x,dict):out.add(str(x.get("id") or x.get("name") or digest(x)))
                else:out.add(str(x))
            return out
        for x in sorted(ids(bv)-ids(av)):
            findings.append({"type":f"unexpected_harness_{label}","severity":"critical","value":x})
    return {"schema":"ai-dfir/harness-diff/v1.1","approved":a,"suspect":b,"findings":findings}

def analyze_lifecycle(path):
    rows=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:rows.append(json.loads(line))
            except Exception:pass
    findings=[];stop_at={};counts=Counter()
    for e in rows:
        et=e.get("event_type") or e.get("type");counts[et]+=1
        sid=e.get("session_id") or e.get("agent_id") or "default"
        if et in ("stop_requested","cancel_requested","containment_applied"):
            stop_at[sid]=e.get("timestamp_utc")
        elif sid in stop_at and et in ("model_call","tool_call","delegation","code_execution","network_action"):
            findings.append({"type":"post_stop_harness_activity","severity":"critical",
                             "session_or_agent":sid,"stop_timestamp":stop_at[sid],"event":e})
        if et=="approval_bypassed":
            findings.append({"type":"harness_approval_bypass","severity":"critical","event":e})
        if et=="prompt_rewrite" and (e.get("metadata") or {}).get("unapproved"):
            findings.append({"type":"unapproved_prompt_assembly_change","severity":"critical","event":e})
    return {"schema":"ai-dfir/harness-lifecycle-analysis/v1.1","events":len(rows),
            "event_counts":dict(counts),"findings":findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    p=sp.add_parser("lifecycle");p.add_argument("--log",required=True);p.add_argument("--out")
    a=ap.parse_args()
    obj=diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text())) if a.cmd=="diff" else analyze_lifecycle(a.log)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
