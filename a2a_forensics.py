#!/usr/bin/env python3
"""
A2A v1.0 forensic inventory, signed-card-aware diff, and task/context analysis.

Passive analysis only: this tool does not contact remote agents.
"""
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

def canon(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def digest(o):return hashlib.sha256(canon(o)).hexdigest()

def normalize_card(card):
    skills=[]
    for s in card.get("skills") or []:
        skills.append({
            "id":s.get("id"),"name":s.get("name"),
            "description_sha256":hashlib.sha256((s.get("description") or "").encode()).hexdigest(),
            "input_modes":sorted(s.get("inputModes") or s.get("input_modes") or []),
            "output_modes":sorted(s.get("outputModes") or s.get("output_modes") or []),
            "tags":sorted(s.get("tags") or []),
        })
    interfaces=card.get("supportedInterfaces") or card.get("supported_interfaces") or []
    return {
        "name":card.get("name"),"version":card.get("version"),
        "provider":card.get("provider"),
        "supported_interfaces_sha256":digest(interfaces),
        "security_schemes_sha256":digest(card.get("securitySchemes") or card.get("security_schemes") or {}),
        "capabilities_sha256":digest(card.get("capabilities") or {}),
        "skills":sorted(skills,key=lambda x:str(x["id"])),
        "extensions_sha256":digest(card.get("extensions") or []),
        "card_sha256":digest(card),
    }

def diff_cards(approved,suspect):
    a,b=normalize_card(approved),normalize_card(suspect);findings=[]
    for field,sev in [
        ("version","high"),("provider","critical"),("supported_interfaces_sha256","critical"),
        ("security_schemes_sha256","critical"),("capabilities_sha256","high"),
        ("extensions_sha256","high")
    ]:
        if a.get(field)!=b.get(field):
            findings.append({"type":f"a2a_{field}_changed","severity":sev,
                             "approved":a.get(field),"suspect":b.get(field)})
    ask={x["id"]:x for x in a["skills"]};bsk={x["id"]:x for x in b["skills"]}
    for sid in sorted(set(bsk)-set(ask)):
        findings.append({"type":"a2a_unexpected_skill","severity":"critical","skill_id":sid})
    for sid in sorted(set(ask)&set(bsk)):
        if ask[sid]!=bsk[sid]:
            findings.append({"type":"a2a_skill_changed","severity":"critical","skill_id":sid,
                             "approved":ask[sid],"suspect":bsk[sid]})
    return {"schema":"ai-dfir/a2a-card-diff/v1.3","approved":a,"suspect":b,"findings":findings}

def load_jsonl(path):
    out=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def analyze_events(rows,approved_push_hosts=None):
    approved=set(approved_push_hosts or [])
    tasks={};contexts=defaultdict(set);findings=[];cards=defaultdict(set)
    for e in rows:
        et=e.get("event_type") or e.get("type")
        tid=e.get("task_id");cid=e.get("context_id")
        if tid:
            t=tasks.setdefault(tid,{"task_id":tid,"owners":set(),"agents":set(),"states":[],"push_urls":set()})
            if e.get("principal"):t["owners"].add(e["principal"])
            if e.get("agent_id"):t["agents"].add(e["agent_id"])
            if e.get("status") or e.get("state"):t["states"].append(e.get("status") or e.get("state"))
            if e.get("push_notification_url"):t["push_urls"].add(e["push_notification_url"])
        if cid and tid:contexts[cid].add(tid)
        if e.get("agent_card_sha256") and e.get("agent_id"):cards[e["agent_id"]].add(e["agent_card_sha256"])
        if et=="task_access" and e.get("expected_principal") and e.get("principal")!=e.get("expected_principal"):
            findings.append({"type":"a2a_task_owner_mismatch","severity":"critical","event":e})
        if et=="context_access" and e.get("expected_context_id") and cid!=e.get("expected_context_id"):
            findings.append({"type":"a2a_context_hijack","severity":"critical","event":e})
        url=e.get("push_notification_url")
        if url:
            host=urlparse(url).hostname
            if approved and host not in approved:
                findings.append({"type":"a2a_unapproved_push_notification_host","severity":"critical","host":host,"event":e})
        if et=="agent_card_used" and e.get("signature_valid") is False:
            findings.append({"type":"a2a_agent_card_signature_invalid","severity":"critical","event":e})
    for tid,t in tasks.items():
        if len(t["owners"])>1:
            findings.append({"type":"a2a_task_multiple_owners","severity":"critical","task_id":tid,"owners":sorted(t["owners"])})
    for aid,hashes in cards.items():
        if len(hashes)>1:
            findings.append({"type":"a2a_agent_card_changed_during_observation","severity":"high","agent_id":aid,"hashes":sorted(hashes)})
    serial={k:{**v,"owners":sorted(v["owners"]),"agents":sorted(v["agents"]),"push_urls":sorted(v["push_urls"])}
            for k,v in tasks.items()}
    return {"schema":"ai-dfir/a2a-event-analysis/v1.3","tasks":serial,
            "contexts":{k:sorted(v) for k,v in contexts.items()},
            "agent_card_hashes":{k:sorted(v) for k,v in cards.items()},
            "findings":findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("diff-card");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    p=sp.add_parser("events");p.add_argument("--log",required=True);p.add_argument("--approved-push-host",action="append",default=[]);p.add_argument("--out")
    a=ap.parse_args()
    obj=diff_cards(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text())) if a.cmd=="diff-card" else analyze_events(load_jsonl(a.log),a.approved_push_host)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
