#!/usr/bin/env python3
"""Evaluate service/collector SLO probe results for distributed AI-DFIR."""
from __future__ import annotations
import argparse,json
from pathlib import Path

def assess(probes,policy):
    fs=[]
    for p in probes:
        name=p.get('name');avail=float(p.get('availability_percent',0));lag=float(p.get('max_ingest_lag_seconds',1e9));err=float(p.get('error_percent',100))
        q=policy.get(name,policy.get('default',{}));
        if avail<float(q.get('min_availability_percent',99.0)):fs.append({'type':'slo_availability_breach','severity':'critical','service':name,'actual':avail})
        if lag>float(q.get('max_ingest_lag_seconds',300)):fs.append({'type':'slo_ingest_lag_breach','severity':'critical','service':name,'actual':lag})
        if err>float(q.get('max_error_percent',1.0)):fs.append({'type':'slo_error_rate_breach','severity':'high','service':name,'actual':err})
    return {'schema':'ai-dfir/service-slo/v1.5','pass':not any(x['severity']=='critical' for x in fs),'probe_count':len(probes),'findings':fs}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--probes',required=True);ap.add_argument('--policy',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(json.loads(Path(a.probes).read_text()),json.loads(Path(a.policy).read_text()));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['pass'] else 2)
if __name__=='__main__':main()
