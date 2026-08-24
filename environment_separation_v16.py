#!/usr/bin/env python3
"""Validate LAB/STAGING/PRODUCTION trust-domain and endpoint separation."""
from __future__ import annotations
import argparse,json
from pathlib import Path

def load(p):return json.loads(Path(p).read_text())
def analyze(cfg):
    envs=cfg.get('environments') or {};findings=[]
    required={'lab','staging','production'}
    missing=required-set(envs)
    for e in sorted(missing):findings.append({'type':'environment_missing','severity':'critical','environment':e})
    def value(env,key):return (envs.get(env) or {}).get(key)
    for key in ('spiffe_trust_domain','metadata_dsn','object_store_bucket','kms_key_id','oidc_audience'):
        vals={e:value(e,key) for e in required if value(e,key)}
        rev={}
        for e,v in vals.items():rev.setdefault(str(v),[]).append(e)
        for v,names in rev.items():
            if len(names)>1:findings.append({'type':'environment_control_reused','severity':'critical','control':key,'value':v,'environments':sorted(names)})
    prod=envs.get('production') or {}
    if prod.get('allows_synthetic_malware_execution') is True:findings.append({'type':'production_allows_test_execution','severity':'critical'})
    if prod.get('default_egress')!='deny':findings.append({'type':'production_egress_not_deny_by_default','severity':'critical'})
    return {'schema':'ai-dfir/environment-separation/v1.6','valid':not any(x['severity']=='critical' for x in findings),'findings':findings,'environments':sorted(envs)}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--out');a=ap.parse_args();o=analyze(load(a.config));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
