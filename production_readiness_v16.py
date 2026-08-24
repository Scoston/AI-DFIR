#!/usr/bin/env python3
"""AI-DFIR v1.6 final evidence-backed production readiness gate."""
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone,timedelta
from pathlib import Path

def load(p):
    try:return json.loads(Path(p).read_text())
    except Exception:return None
def recent(o,max_days):
    try:
        s=o.get('validated_utc') or o.get('created_utc') or o.get('completed_utc');t=datetime.fromisoformat(str(s).replace('Z','+00:00'));return datetime.now(timezone.utc)-t<=timedelta(days=max_days)
    except Exception:return False

def assess(config,base=None):
    findings=[];checks=[]
    def ck(name,obj,good,fresh_days=None,severity='critical'):
        ok=bool(obj and good(obj));fresh=True if fresh_days is None else bool(obj and recent(obj,fresh_days));passed=ok and fresh
        checks.append({'control':name,'pass':passed,'fresh':fresh,'evidence':obj})
        if not passed:findings.append({'type':'production_readiness_control_failed','severity':severity,'control':name,'fresh':fresh})
    base=base or load(config.get('v15_readiness_result'))
    ck('v15_enterprise_controls',base,lambda x:x.get('production_ready') is True,30)
    specs=[
      ('platform_assurance','platform_assurance',lambda x:x.get('status')=='HEALTHY',1),
      ('environment_separation','environment_separation',lambda x:x.get('valid') is True,30),
      ('chaos_validation','chaos_validation',lambda x:x.get('valid') is True,90),
      ('release_integrity','release_integrity',lambda x:x.get('valid') is True,30),
      ('security_assurance','security_assurance',lambda x:x.get('valid') is True,365),
      ('upgrade_assurance','upgrade_assurance',lambda x:x.get('valid') is True,180),
      ('network_policy_validation','network_policy_validation',lambda x:x.get('valid') is True,30),
    ]
    for name,key,fn,days in specs:ck(name,load(config.get(key)),fn,days)
    certs=[load(x) for x in config.get('provider_certifications',[])];ck('provider_certifications',{'validated_utc':datetime.now(timezone.utc).isoformat(),'certified':bool(certs) and all(x and x.get('certified') for x in certs)},lambda x:x.get('certified') is True,1)
    slo=load(config.get('service_slo'));ck('service_slo',slo,lambda x:x.get('pass') is True,7)
    bench=load(config.get('scale_benchmark'));ck('production_scale_benchmark',bench,lambda x:x.get('deployment_benchmark') is True and x.get('backend')=='postgres',90)
    overall=not any(x['severity']=='critical' for x in findings)
    return {'schema':'ai-dfir/production-readiness/v1.6','validated_utc':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'production_ready':overall,'checks':checks,'findings':findings,
            'rule':'Production readiness requires current control evidence. This result expires as underlying evidence ages.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--base-result');ap.add_argument('--out');a=ap.parse_args();cfg=load(a.config) or {};base=load(a.base_result) if a.base_result else None;o=assess(cfg,base);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['production_ready'] else 2)
if __name__=='__main__':main()
