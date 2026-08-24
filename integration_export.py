#!/usr/bin/env python3
"""Read-only SIEM/SOAR/STIX-friendly export of AI-DFIR findings and case state."""
from __future__ import annotations
import argparse,json,uuid
from datetime import datetime,timezone
from pathlib import Path
from case_model import full_case

def flatten_findings(obj,prefix=''):
    out=[]
    if isinstance(obj,dict):
        if obj.get('type') and obj.get('severity'):out.append({'domain':prefix,'finding':obj})
        for k,v in obj.items():out+=flatten_findings(v,f'{prefix}.{k}' if prefix else k)
    elif isinstance(obj,list):
        for v in obj:out+=flatten_findings(v,prefix)
    return out

def export(case_root):
    case=full_case(Path(case_root));findings=flatten_findings(case);now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    ecs=[]
    for x in findings:
        f=x['finding'];ecs.append({'@timestamp':now,'event.kind':'alert','event.category':['intrusion_detection'],'event.type':['info'],'event.dataset':'ai-dfir','rule.name':f.get('type'),'event.severity':f.get('severity'),'ai_dfir.domain':x['domain'],'ai_dfir.case_id':(case.get('summary') or {}).get('case_id'),'message':json.dumps(f,sort_keys=True,default=str)})
    stix=[]
    for x in findings:
        f=x['finding'];stix.append({'type':'note','spec_version':'2.1','id':'note--'+str(uuid.uuid4()),'created':now,'modified':now,'abstract':f.get('type'),'content':json.dumps(f,sort_keys=True,default=str),'labels':['ai-dfir',str(f.get('severity'))]})
    return {'schema':'ai-dfir/integration-export/v1.4','ecs_events':ecs,'stix_bundle':{'type':'bundle','id':'bundle--'+str(uuid.uuid4()),'objects':stix},'finding_count':len(findings)}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True);ap.add_argument('--out',required=True);a=ap.parse_args();o=export(a.case);Path(a.out).write_text(json.dumps(o,indent=2,sort_keys=True,default=str));print(json.dumps({'findings':o['finding_count'],'out':a.out},indent=2))
if __name__=='__main__':main()
