#!/usr/bin/env python3
"""End-to-end A2A v1.3 trust, history and execution-binding case analysis."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from a2a_jcs import strict_load
from a2a_trust_store import load_store
from a2a_agent_card_crypto import verify_card
from a2a_card_history import compare
from a2a_execution_binding import analyze as bind_execution,load_jsonl

HERE=Path(__file__).resolve().parent
def read(p):return json.loads(Path(p).read_text())
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
def signals(o):
    out=set()
    if isinstance(o,list):
        for x in o:out|=signals(x)
    elif isinstance(o,dict):
        if o.get("type"):out.add(o["type"])
        for k in ("findings","signatures"):
            if k in o:out|=signals(o[k])
    return out
def attach(case,packs):
    p=case/"incident_profile.json";obj=read(p) if p.exists() else {"schema":"ai-dfir/incident-profile/v1.3"}
    cur=list(obj.get("additional_evidence_pack_ids") or [])
    for x in sorted(packs):
        if x not in cur and x!=obj.get("evidence_pack_id"):cur.append(x)
    obj["schema"]="ai-dfir/incident-profile/v1.3";obj["additional_evidence_pack_ids"]=sorted(cur)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True))

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--case",required=True);ap.add_argument("--card",required=True)
    ap.add_argument("--trust-store",required=True);ap.add_argument("--trust-public-key");ap.add_argument("--allow-unsigned-trust-store",action="store_true")
    ap.add_argument("--previous-card");ap.add_argument("--events")
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True)
    store,meta=load_store(a.trust_store,a.trust_public_key,a.allow_unsigned_trust_store)
    card=strict_load(a.card)
    verification=verify_card(card,store);verification["trust_store"]=meta
    write(case/"a2a_agent_card_verification.json",verification)
    objs=[verification];generated=[str(case/"a2a_agent_card_verification.json")]
    if a.previous_card:
        h=compare(strict_load(a.previous_card),card);write(case/"a2a_card_history.json",h);objs.append(h);generated.append(str(case/"a2a_card_history.json"))
    if a.events:
        b=bind_execution(load_jsonl(a.events),verification);write(case/"a2a_execution_binding.json",b);objs.append(b);generated.append(str(case/"a2a_execution_binding.json"))
    sig=set()
    for o in objs:sig|=signals(o)
    rules=read(HERE/"a2a_trust_rules.json");packs=set();matches=[]
    for r in rules["rules"]:
        hit=sorted(set(r["signals"])&sig)
        if hit:packs.add(r["pack"]);matches.append({"pack_id":r["pack"],"severity":r["severity"],"matched_signals":hit})
    attach(case,packs)
    result={"schema":"ai-dfir/a2a-trust-run/v1.3","generated":generated,"signals":sorted(sig),
            "attached_packs":sorted(packs),"evidence_pack_matches":matches,
            "policy_satisfied":verification["policy_satisfied"],"trusted":verification["trusted"]}
    write(case/"a2a_trust_run.json",result);print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__":main()
