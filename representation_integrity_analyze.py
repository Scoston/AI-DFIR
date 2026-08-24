#!/usr/bin/env python3
"""Run v1.2 representation-integrity analysis and attach matching Evidence Packs."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from content_intake_gate import scan as intake_scan
from representation_differential import analyze as representation_diff
from network_exfil_forensics import analyze as network_analyze,load as load_network
from approval_integrity import analyze as approval_analyze
from session_state_integrity import compare as session_compare
from ide_surface_forensics import inventory as ide_inventory,diff as ide_diff

HERE=Path(__file__).resolve().parent
def read(p):return json.loads(Path(p).read_text())
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
def signalset(o):
    out=set()
    if isinstance(o,list):
        for x in o:out |= signalset(x)
    elif isinstance(o,dict):
        if o.get("type"):out.add(o["type"])
        for k in ("findings","analyses"):
            v=o.get(k)
            if isinstance(v,dict):
                for z in v.values():out |= signalset(z)
            elif v is not None:out |= signalset(v)
    return out
def attach(case,packs):
    p=case/"incident_profile.json";obj=read(p) if p.exists() else {"schema":"ai-dfir/incident-profile/v1.2"}
    cur=list(obj.get("additional_evidence_pack_ids") or [])
    for x in packs:
        if x and x!=obj.get("evidence_pack_id") and x not in cur:cur.append(x)
    obj["schema"]="ai-dfir/incident-profile/v1.2";obj["additional_evidence_pack_ids"]=sorted(cur)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--case",required=True)
    ap.add_argument("--content")
    ap.add_argument("--machine-text");ap.add_argument("--visible-text")
    ap.add_argument("--network-log");ap.add_argument("--approved-domain",action="append",default=[])
    ap.add_argument("--approval-records")
    ap.add_argument("--session");ap.add_argument("--session-checkpoint");ap.add_argument("--session-public-key")
    ap.add_argument("--ide-approved-root");ap.add_argument("--ide-suspect-root")
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True)
    generated=[];signals=set()
    def emit(name,obj):
        p=case/name;write(p,obj);generated.append(str(p));signals.update(signalset(obj));return obj
    if a.content:emit("content_intake_analysis.json",intake_scan(a.content))
    if a.machine_text and a.visible_text:
        emit("representation_differential.json",representation_diff(
            Path(a.machine_text).read_text(encoding="utf-8",errors="replace"),
            Path(a.visible_text).read_text(encoding="utf-8",errors="replace"),
            a.machine_text,a.visible_text))
    if a.network_log:emit("network_exfil_analysis.json",network_analyze(load_network(a.network_log),a.approved_domain))
    if a.approval_records:
        o=read(a.approval_records);emit("approval_integrity_analysis.json",approval_analyze(o.get("records",o)))
    if a.session and a.session_checkpoint and a.session_public_key:
        emit("session_state_integrity.json",session_compare(a.session,a.session_checkpoint,a.session_public_key))
    if a.ide_approved_root and a.ide_suspect_root:
        emit("ide_surface_diff.json",ide_diff(ide_inventory(a.ide_approved_root),ide_inventory(a.ide_suspect_root)))
    rules=read(HERE/"representation_integrity_rules.json");matches=[];packs=set()
    for r in rules["rules"]:
        hit=sorted(set(r["signals"])&signals)
        if hit:
            packs.add(r["pack"]);matches.append({"pack_id":r["pack"],"severity":r["severity"],"matched_signals":hit})
    attach(case,packs)
    result={"schema":"ai-dfir/representation-integrity-run/v1.2","generated":generated,
            "signals":sorted(signals),"evidence_pack_matches":matches,"attached_packs":sorted(packs)}
    write(case/"representation_integrity_run.json",result);print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__":main()
