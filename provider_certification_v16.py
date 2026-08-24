#!/usr/bin/env python3
"""Provider collector certification matrix for AI-DFIR v1.6.

Certification is evidence-backed: a provider is not marked certified just because
an adapter exists. Test receipts must prove authentication, pagination, throttling,
time-window handling and evidence-gap behavior against the target API/version.
"""
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone,timedelta
from pathlib import Path

REQUIRED_TESTS=['authentication','pagination','rate_limit_recovery','time_window','schema_normalization','evidence_gap_reporting','negative_permission_case']
def load(p):return json.loads(Path(p).read_text())
def iso(s):
    try:return datetime.fromisoformat(str(s).replace('Z','+00:00'))
    except Exception:return None

def certify(profile,receipts,now=None):
    now=now or datetime.now(timezone.utc);by={r.get('test'):r for r in receipts};findings=[];tests=[]
    max_age=int(profile.get('max_certification_age_days',90))
    for t in REQUIRED_TESTS:
        r=by.get(t);passed=bool(r and r.get('pass') is True);ts=iso((r or {}).get('validated_utc'));fresh=bool(ts and now-ts<=timedelta(days=max_age))
        tests.append({'test':t,'pass':passed,'fresh':fresh,'receipt':r})
        if not passed:findings.append({'type':'provider_certification_test_failed','severity':'critical','test':t})
        elif not fresh:findings.append({'type':'provider_certification_test_stale','severity':'high','test':t})
    api=profile.get('api_version'); versions={r.get('api_version') for r in receipts if r.get('api_version')}
    if api and versions and api not in versions:findings.append({'type':'provider_api_version_not_certified','severity':'critical','expected':api,'observed':sorted(versions)})
    certified=not any(x['severity']=='critical' for x in findings) and all(x['fresh'] for x in tests)
    return {'schema':'ai-dfir/provider-certification/v1.6','provider':profile.get('provider'),'adapter':profile.get('adapter'),'api_version':api,
            'validated_utc':now.isoformat().replace('+00:00','Z'),'certified':certified,'tests':tests,'findings':findings,
            'limitations':profile.get('known_limitations') or [],'rule':'Adapter existence is not provider certification. Certification is versioned and expires.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--profile',required=True);ap.add_argument('--receipts',required=True);ap.add_argument('--out');a=ap.parse_args();o=certify(load(a.profile),load(a.receipts));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['certified'] else 2)
if __name__=='__main__':main()
