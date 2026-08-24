#!/usr/bin/env python3
"""Attach v1.5 enterprise Evidence Packs from normalized enterprise artifacts.

The orchestrator is deliberately read-only with respect to source evidence. It
reads already acquired/validated enterprise artifacts inside a case, emits a
small run summary, and updates only the case's incident profile pack selection.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from case_model import enterprise_v15

HERE=Path(__file__).resolve().parent

def read(p):return json.loads(Path(p).read_text())
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
def collect_signals(o):
    out=set()
    if isinstance(o,dict):
        if o.get('type'):out.add(o['type'])
        for v in o.values():out|=collect_signals(v)
    elif isinstance(o,list):
        for v in o:out|=collect_signals(v)
    return out

def attach(case,packs):
    p=case/'incident_profile.json';obj=read(p) if p.exists() else {'schema':'ai-dfir/incident-profile/v1.5'}
    cur=list(obj.get('additional_evidence_pack_ids') or [])
    for x in sorted(packs):
        if x not in cur and x!=obj.get('evidence_pack_id'):cur.append(x)
    obj['schema']='ai-dfir/incident-profile/v1.5';obj['additional_evidence_pack_ids']=sorted(cur);write(p,obj)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True);a=ap.parse_args();case=Path(a.case).resolve()
    state=enterprise_v15(case);sig=collect_signals(state);rules=read(HERE/'enterprise_v15_rules.json');packs=set();matches=[]
    for r in rules['rules']:
        hit=sorted(set(r['signals'])&sig)
        if hit:packs.add(r['pack']);matches.append({'pack_id':r['pack'],'severity':r.get('severity'),'matched_signals':hit})
    # Positive enterprise objects can also select evidence packs when the
    # investigation explicitly includes them even if they have no finding.
    presence=state.get('presence') or {}
    positive={
      'oidc_identity':'enterprise.oidc_identity','spiffe_identity':'enterprise.spiffe_service_identity',
      'object_store':'enterprise.object_storage_integrity','dr_restore':'enterprise.dr_restore',
      'a2a_request_provenance':'enterprise.a2a_request_provenance','case_export':'enterprise.case_export',
      'scale_benchmark':'enterprise.scale_capacity','distributed_acquisition':'enterprise.distributed_collection',
      'production_readiness':'enterprise.production_readiness'
    }
    for domain,pid in positive.items():
        if presence.get(domain):packs.add(pid)
    if state.get('provider_gaps'):packs.add('enterprise.provider_collection_gap')
    if state.get('provider_receipts'):packs.add('enterprise.native_provider_collection')
    if presence.get('legal_hold'):packs.add('enterprise.legal_hold')
    attach(case,packs)
    result={'schema':'ai-dfir/enterprise-v15-run/v1.5','signals':sorted(sig),'attached_packs':sorted(packs),
            'evidence_pack_matches':matches,'mandatory_provider_collection_complete':state.get('mandatory_provider_collection_complete'),
            'finding_count':len(state.get('findings') or [])}
    write(case/'enterprise_v15_run.json',result);print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
