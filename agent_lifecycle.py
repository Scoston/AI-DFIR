#!/usr/bin/env python3
"""Cryptographically signed agent birth/death certificates and orphan detection."""
from __future__ import annotations
import argparse, json, uuid
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def birth(private_key,out,agent_id,parent_id,purpose,model,harness,authority,expires_utc=None,children_allowed=False,config_hashes=None):
    p={"schema":"ai-dfir/agent-birth/v1.1","certificate_id":str(uuid.uuid4()),"agent_id":agent_id,
       "parent_agent_id":parent_id,"purpose":purpose,"model":model,"harness":harness,
       "authority":authority,"created_utc":utc(),"expires_utc":expires_utc,
       "children_allowed":bool(children_allowed),"config_hashes":config_hashes or {}}
    env=sign_payload(Path(private_key),p);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def death(private_key,out,agent_id,reason,last_task=None,last_tool=None,open_children=None,open_consequences=None,credentials_revoked=None,memory_disposition=None):
    p={"schema":"ai-dfir/agent-death/v1.1","certificate_id":str(uuid.uuid4()),"agent_id":agent_id,
       "terminated_utc":utc(),"reason":reason,"last_task":last_task,"last_tool":last_tool,
       "open_children":open_children or [],"open_consequences":open_consequences or [],
       "credentials_revoked":credentials_revoked,"memory_disposition":memory_disposition}
    env=sign_payload(Path(private_key),p);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def analyze(births,deaths,observed_agents):
    b={x["payload"]["agent_id"]:x["payload"] for x in births}
    d={x["payload"]["agent_id"]:x["payload"] for x in deaths}
    findings=[]
    for aid in sorted(set(observed_agents)-set(b)):
        findings.append({"type":"agent_without_birth_certificate","severity":"critical","agent_id":aid})
    for aid,x in b.items():
        if x.get("parent_agent_id") and x["parent_agent_id"] not in b:
            findings.append({"type":"agent_parent_certificate_missing","severity":"high","agent_id":aid,"parent":x["parent_agent_id"]})
        parent=b.get(x.get("parent_agent_id"))
        if parent and not parent.get("children_allowed"):
            findings.append({"type":"unauthorized_child_agent","severity":"critical","agent_id":aid,"parent":x["parent_agent_id"]})
    for aid,x in d.items():
        if x.get("open_children"):
            findings.append({"type":"terminated_agent_has_open_children","severity":"critical","agent_id":aid,"children":x["open_children"]})
        if x.get("open_consequences"):
            findings.append({"type":"terminated_agent_has_open_consequences","severity":"high","agent_id":aid,"consequences":x["open_consequences"]})
    return {"schema":"ai-dfir/agent-lifecycle-analysis/v1.1","findings":findings,
            "birth_count":len(b),"death_count":len(d),"observed_agents":sorted(observed_agents)}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("birth");p.add_argument("--private-key",required=True);p.add_argument("--out",required=True);p.add_argument("--agent-id",required=True);p.add_argument("--parent");p.add_argument("--purpose",required=True);p.add_argument("--model",required=True);p.add_argument("--harness",required=True);p.add_argument("--authority",required=True);p.add_argument("--expires");p.add_argument("--children-allowed",action="store_true")
    p=sp.add_parser("death");p.add_argument("--private-key",required=True);p.add_argument("--out",required=True);p.add_argument("--agent-id",required=True);p.add_argument("--reason",required=True)
    a=ap.parse_args()
    if a.cmd=="birth":print(json.dumps(birth(a.private_key,a.out,a.agent_id,a.parent,a.purpose,a.model,a.harness,a.authority,a.expires,a.children_allowed),indent=2))
    else:print(json.dumps(death(a.private_key,a.out,a.agent_id,a.reason),indent=2))
if __name__=="__main__":main()
