#!/usr/bin/env python3
"""Evaluate externally executed failover/chaos drills. Does not inject failures itself."""
from __future__ import annotations
import argparse,json
from pathlib import Path
REQUIRED=['database_primary_loss','collector_worker_loss','provider_api_outage','object_store_transient_failure','kms_unavailable','identity_provider_outage','clock_skew']
def load(p):return json.loads(Path(p).read_text())
def assess(results,policy):
    by={x.get('scenario'):x for x in results};findings=[];rows=[]
    for s in REQUIRED:
        r=by.get(s);p=(policy.get('scenarios') or {}).get(s,{})
        ok=bool(r and r.get('pass') is True)
        if r and p.get('max_recovery_seconds') is not None:ok=ok and float(r.get('recovery_seconds',1e99))<=float(p['max_recovery_seconds'])
        if r and p.get('max_data_loss_events') is not None:ok=ok and int(r.get('data_loss_events',1e99))<=int(p['max_data_loss_events'])
        rows.append({'scenario':s,'pass':ok,'result':r,'policy':p})
        if not ok:findings.append({'type':'chaos_scenario_failed_or_missing','severity':'critical','scenario':s})
    return {'schema':'ai-dfir/chaos-validation/v1.6','valid':not findings,'results':rows,'findings':findings,
            'rule':'This evaluator consumes controlled drill results. AI-DFIR does not trigger destructive production chaos.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--results',required=True);ap.add_argument('--policy',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(load(a.results),load(a.policy));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
