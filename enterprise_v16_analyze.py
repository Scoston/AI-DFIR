#!/usr/bin/env python3
"""Attach v1.6 production-assurance findings to an AI-DFIR case.

The analyzer ingests already-generated control evidence. It does not contact
production infrastructure itself; control-specific tools produce those probes.
"""
from __future__ import annotations
import argparse,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent

def read(p):return json.loads(Path(p).read_text())
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
def sigs(o):
    out=set()
    if isinstance(o,list):
        for x in o:out|=sigs(x)
    elif isinstance(o,dict):
        if o.get('type'):out.add(o['type'])
        for k in ('findings','controls','tests','checks','results'):
            if k in o:out|=sigs(o[k])
    return out

def attach(case,packs):
    p=case/'incident_profile.json';obj=read(p) if p.exists() else {'schema':'ai-dfir/incident-profile/v1.6'}
    cur=list(obj.get('additional_evidence_pack_ids') or [])
    for x in sorted(packs):
        if x not in cur and x!=obj.get('evidence_pack_id'):cur.append(x)
    obj['schema']='ai-dfir/incident-profile/v1.6';obj['additional_evidence_pack_ids']=sorted(cur);write(p,obj)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True)
    for name in ('platform-assurance','provider-certification','environment-separation','chaos-validation','release-integrity','security-assurance','upgrade-assurance','network-policy-validation','schema-migration'):
        ap.add_argument('--'+name,action='append',default=[])
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True);objs=[];generated=[]
    mapping={k.replace('_','-'):v for k,v in vars(a).items() if isinstance(v,list)}
    for kind,paths in mapping.items():
        for i,path in enumerate(paths):
            o=read(path);objs.append(o);dest=case/(kind.replace('-','_')+('' if len(paths)==1 else f'_{i+1}')+'.json');write(dest,o);generated.append(str(dest))
    signals=set();
    for o in objs:signals|=sigs(o)
    rules=read(HERE/'production_assurance_rules.json');packs=set();matches=[]
    for r in rules['rules']:
        hit=sorted(set(r.get('signals') or [])&signals)
        if hit:packs.add(r['pack']);matches.append({'pack_id':r['pack'],'matched_signals':hit})
    attach(case,packs)
    result={'schema':'ai-dfir/enterprise-v16-run/v1.6','signals':sorted(signals),'attached_packs':sorted(packs),'matches':matches,'generated':generated}
    write(case/'enterprise_v16_run.json',result);print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
