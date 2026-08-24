#!/usr/bin/env python3
"""
Bind observed A2A execution events to verified Agent Card identity and delegated authority.

The current A2A v1.0 Agent Card JWS protects the Agent Card, not every A2A request.
This analyzer therefore does not claim per-request cryptographic identity unless
the event source independently supplies such evidence.
"""
from __future__ import annotations
import argparse,json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

def load_jsonl(path):
    out=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:
                obj=json.loads(line)
                if isinstance(obj,list):out.extend(x for x in obj if isinstance(x,dict))
                elif isinstance(obj,dict):out.append(obj)
            except Exception:pass
    return out

def analyze(events,verification,authority=None):
    findings=[];card=verification.get("card_identity") or {}
    declared_skills=set(card.get("skills") or [])
    trusted=bool(verification.get("policy_satisfied") and verification.get("trusted"))
    interfaces=card.get("interfaces") or []
    declared_tenants={x.get("tenant") for x in interfaces if x.get("tenant") is not None}
    iface_origins=set()
    for x in interfaces:
        try:
            u=urlparse(x.get("url",""));iface_origins.add(f"{u.scheme}://{u.netloc}")
        except Exception:pass
    tasks=defaultdict(lambda:{"agents":set(),"contexts":set(),"principals":set(),"skills":set(),"tenants":set()})
    for e in events:
        tid=e.get("task_id");cid=e.get("context_id");skill=e.get("skill_id")
        if not trusted:
            findings.append({"type":"a2a_execution_bound_to_untrusted_agent_card","severity":"critical","event_id":e.get("event_id")})
        observed=e.get("agent_card_sha256")
        expected=verification.get("canonical_payload_sha256")
        if observed and expected and observed!=expected:
            findings.append({"type":"a2a_execution_card_hash_mismatch","severity":"critical","event_id":e.get("event_id"),"observed":observed,"expected":expected})
        if skill and skill not in declared_skills:
            findings.append({"type":"a2a_undeclared_skill_invoked","severity":"critical","skill_id":skill,"event_id":e.get("event_id")})
        tenant=e.get("tenant")
        if declared_tenants and tenant not in declared_tenants:
            findings.append({"type":"a2a_tenant_binding_mismatch","severity":"critical","tenant":tenant,"declared":sorted(declared_tenants)})
        if e.get("callback_url"):
            try:
                u=urlparse(e["callback_url"]);o=f"{u.scheme}://{u.netloc}"
                if iface_origins and o in iface_origins and e.get("callback_role")=="client":
                    findings.append({"type":"a2a_callback_points_to_agent_interface","severity":"high","callback_url":e["callback_url"]})
            except Exception:pass
        before=e.get("authority_before") or []
        after=e.get("authority_after") or []
        if set(after)-set(before) and not e.get("authority_elevation_approved",False):
            findings.append({"type":"a2a_unapproved_authority_escalation","severity":"critical","event_id":e.get("event_id"),"added":sorted(set(after)-set(before))})
        if tid:
            t=tasks[tid]
            if e.get("agent_id"):t["agents"].add(e["agent_id"])
            if cid:t["contexts"].add(cid)
            if e.get("principal"):t["principals"].add(e["principal"])
            if skill:t["skills"].add(skill)
            if tenant is not None:t["tenants"].add(tenant)
    for tid,t in tasks.items():
        if len(t["contexts"])>1:
            findings.append({"type":"a2a_task_context_split","severity":"critical","task_id":tid,"contexts":sorted(t["contexts"])})
        if len(t["principals"])>1:
            findings.append({"type":"a2a_task_principal_drift","severity":"critical","task_id":tid,"principals":sorted(t["principals"])})
    serial={k:{x:sorted(v) for x,v in t.items()} for k,t in tasks.items()}
    return {"schema":"ai-dfir/a2a-execution-binding/v1.3","trusted_agent_card":trusted,
            "card_name":card.get("name"),"tasks":serial,"findings":findings,
            "limitation":"Agent Card JWS authenticates the card. Per-request sender authenticity requires transport/authentication evidence or a separate request-signature mechanism."}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--events",required=True);ap.add_argument("--verification",required=True);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load_jsonl(a.events),json.loads(Path(a.verification).read_text()))
    text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
