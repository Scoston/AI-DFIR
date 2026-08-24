#!/usr/bin/env python3
"""Credential/token lineage and incident-time validity analysis without storing secret token material."""
from __future__ import annotations
import argparse,json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def dt(s):return datetime.fromisoformat(str(s).replace('Z','+00:00')) if s else None

def load(p):
    o=json.loads(Path(p).read_text());return o.get('credentials',o if isinstance(o,list) else [])

def analyze(rows,approved_issuers=None):
    approved=set(approved_issuers or []);findings=[];byid={};uses=defaultdict(list)
    for r in rows:
        cid=r.get('credential_id') or r.get('jti') or r.get('token_sha256')
        if not cid:continue
        if r.get('event_type') in ('credential_use','token_use','auth_use'):uses[cid].append(r);continue
        byid[cid]=r
    for cid,c in byid.items():
        issuer=c.get('issuer')
        if approved and issuer not in approved:findings.append({'type':'credential_unapproved_issuer','severity':'critical','credential_id':cid,'issuer':issuer})
        parent=c.get('parent_credential_id')
        if parent and parent not in byid:findings.append({'type':'credential_parent_missing','severity':'high','credential_id':cid,'parent_credential_id':parent})
        if parent and parent in byid:
            old=set(byid[parent].get('scopes') or []);new=set(c.get('scopes') or [])
            if new-old and not c.get('scope_elevation_approved',False):findings.append({'type':'credential_exchange_scope_expansion','severity':'critical','credential_id':cid,'added_scopes':sorted(new-old),'parent':parent})
            if c.get('issuer')!=byid[parent].get('issuer') and not c.get('issuer_exchange_approved',False):findings.append({'type':'credential_cross_issuer_exchange','severity':'critical','credential_id':cid,'parent':parent})
    for cid,evs in uses.items():
        c=byid.get(cid)
        if not c:
            findings.append({'type':'credential_use_without_issuance_evidence','severity':'high','credential_id':cid,'use_count':len(evs)});continue
        nb=dt(c.get('issued_at_utc') or c.get('not_before_utc'));ex=dt(c.get('expires_utc'));rev=dt(c.get('revoked_utc'))
        holders=set()
        for e in evs:
            t=dt(e.get('timestamp_utc'));work=e.get('workload_id') or e.get('spiffe_id');holders.add(work)
            if t and nb and t<nb:findings.append({'type':'credential_used_before_issue','severity':'critical','credential_id':cid,'event':e})
            if t and ex and t>=ex:findings.append({'type':'credential_used_after_expiry','severity':'critical','credential_id':cid,'event':e})
            if t and rev and t>=rev:findings.append({'type':'credential_used_after_revocation','severity':'critical','credential_id':cid,'event':e})
            aud=e.get('audience')
            allowed=set(c.get('audience') if isinstance(c.get('audience'),list) else [c.get('audience')] if c.get('audience') else [])
            if aud and allowed and aud not in allowed:findings.append({'type':'credential_audience_mismatch','severity':'critical','credential_id':cid,'audience':aud,'allowed':sorted(allowed)})
        holders.discard(None)
        if len(holders)>1 and not c.get('shareable',False):findings.append({'type':'credential_shared_across_workloads','severity':'critical','credential_id':cid,'workloads':sorted(holders)})
    lineage=[]
    for cid,c in byid.items():lineage.append({'credential_id':cid,'type':c.get('credential_type'),'parent_credential_id':c.get('parent_credential_id'),'issuer':c.get('issuer'),'subject':c.get('subject'),'audience':c.get('audience'),'scopes':c.get('scopes') or [],'workload_id':c.get('workload_id'),'issued_at_utc':c.get('issued_at_utc'),'expires_utc':c.get('expires_utc'),'revoked_utc':c.get('revoked_utc'),'use_count':len(uses.get(cid,[]))})
    return {'schema':'ai-dfir/credential-lineage/v1.4','credentials':lineage,'findings':findings,
            'rule':'Store credential identifiers/hashes and claims, not bearer secrets. Validity is evaluated at use time.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--approved-issuer',action='append',default=[]);ap.add_argument('--out')
    a=ap.parse_args();o=analyze(load(a.input),a.approved_issuer);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
