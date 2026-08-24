#!/usr/bin/env python3
"""Validate upgrade/rollback rehearsal evidence for production AI-DFIR."""
from __future__ import annotations
import argparse,json
from pathlib import Path

def load(p):return json.loads(Path(p).read_text())
def assess(r):
    findings=[]
    req=['pre_upgrade_backup_verified','migration_applied','post_upgrade_integrity_verified','rollback_tested','rollback_integrity_verified']
    for k in req:
        if r.get(k) is not True:findings.append({'type':'upgrade_assurance_requirement_failed','severity':'critical','requirement':k})
    if r.get('from_version')==r.get('to_version'):findings.append({'type':'upgrade_versions_identical','severity':'high'})
    return {'schema':'ai-dfir/upgrade-assurance/v1.6','valid':not any(x['severity']=='critical' for x in findings),'from_version':r.get('from_version'),'to_version':r.get('to_version'),'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--result',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(load(a.result));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
