#!/usr/bin/env python3
"""Evaluate independent security-assurance evidence without pretending AI-DFIR performed the assessment."""
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone,timedelta
from pathlib import Path

def load(p):return json.loads(Path(p).read_text())
def iso(s):
    try:return datetime.fromisoformat(str(s).replace('Z','+00:00'))
    except Exception:return None

def assess(report,policy,now=None):
    now=now or datetime.now(timezone.utc);findings=[];ts=iso(report.get('completed_utc'));max_days=int(policy.get('max_age_days',365));fresh=bool(ts and now-ts<=timedelta(days=max_days))
    if not report.get('independent_assessor'):findings.append({'type':'independent_assessor_missing','severity':'critical'})
    if not fresh:findings.append({'type':'security_assessment_stale','severity':'critical'})
    for sev in ('critical','high'):
        if int((report.get('unresolved_findings') or {}).get(sev,0))>int((policy.get('max_unresolved') or {}).get(sev,0)):
            findings.append({'type':'unresolved_security_findings_exceed_policy','severity':'critical','finding_severity':sev})
    required=set(policy.get('required_scope') or []);scope=set(report.get('scope') or [])
    for x in sorted(required-scope):findings.append({'type':'security_assessment_scope_missing','severity':'critical','scope_item':x})
    return {'schema':'ai-dfir/security-assurance/v1.6','valid':not findings,'fresh':fresh,'findings':findings,'report_summary':report,
            'rule':'This gate validates metadata from an independent assessment; it is not itself a penetration test.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--report',required=True);ap.add_argument('--policy',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(load(a.report),load(a.policy));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
