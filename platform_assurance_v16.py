#!/usr/bin/env python3
"""AI-DFIR v1.6 continuous platform assurance.

Consumes independently produced control/probe artifacts and calculates the health
of the DFIR platform itself. It never turns missing telemetry into healthy state.
"""
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone,timedelta
from pathlib import Path

REQUIRED={
 'metadata_ha':('postgresql-ha','critical'),
 'immutable_storage':('immutable-storage','critical'),
 'kms':('kms-hsm','critical'),
 'user_identity':('user-identity','critical'),
 'service_identity':('service-identity','critical'),
 'collector_health':('collector-health','critical'),
 'provider_health':('provider-health','critical'),
 'clock':('clock-integrity','critical'),
 'backup_restore':('backup-restore','critical'),
 'transparency':('transparency','high'),
 'release_integrity':('release-integrity','critical'),
 'tenant_isolation':('tenant-isolation','critical'),
 'network_segmentation':('network-segmentation','critical'),
 'admission_policy':('admission-policy','high'),
 'analyst_audit':('analyst-audit','high'),
 'peer_review':('peer-review','high'),
}

def load(path):
    try:return json.loads(Path(path).read_text())
    except Exception:return None

def iso(s):
    try:return datetime.fromisoformat(str(s).replace('Z','+00:00'))
    except Exception:return None

def evaluate(manifest,now=None):
    now=now or datetime.now(timezone.utc);findings=[];controls=[]
    for name,(kind,severity) in REQUIRED.items():
        spec=(manifest.get('controls') or {}).get(name) or {};path=spec.get('evidence');obj=load(path) if path else None
        max_age_h=float(spec.get('max_age_hours',24));ts=iso((obj or {}).get('validated_utc') or (obj or {}).get('created_utc') or (obj or {}).get('timestamp_utc'))
        fresh=bool(ts and now-ts<=timedelta(hours=max_age_h))
        valid=bool(obj and (obj.get('valid') is True or obj.get('pass') is True or obj.get('ready') is True or obj.get('healthy') is True))
        state='HEALTHY' if valid and fresh else ('STALE' if valid and not fresh else 'FAILED' if obj else 'MISSING')
        row={'control':name,'kind':kind,'state':state,'severity':severity,'evidence':path,'fresh':fresh,'validated':valid,'max_age_hours':max_age_h}
        controls.append(row)
        if state!='HEALTHY':findings.append({'type':'platform_assurance_control_'+state.lower(),'severity':severity,'control':name,'evidence':path})
    critical=any(x['severity']=='critical' for x in findings)
    high=any(x['severity']=='high' for x in findings)
    overall='CRITICAL' if critical else 'DEGRADED' if high else 'HEALTHY'
    return {'schema':'ai-dfir/platform-assurance/v1.6','validated_utc':now.isoformat().replace('+00:00','Z'),'status':overall,
            'healthy_controls':sum(x['state']=='HEALTHY' for x in controls),'control_count':len(controls),'controls':controls,'findings':findings,
            'rule':'Platform assurance measures whether the forensic platform can currently produce trustworthy evidence. It is separate from incident attribution.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--manifest',required=True);ap.add_argument('--out');a=ap.parse_args();o=evaluate(load(a.manifest) or {});s=json.dumps(o,indent=2,sort_keys=True)
    Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['status']=='HEALTHY' else 2)
if __name__=='__main__':main()
