#!/usr/bin/env python3
"""Workload identity/SPIFFE-SPIRE forensic analyzer."""
from __future__ import annotations
import argparse,json,hashlib
from datetime import datetime,timezone
from pathlib import Path

def dt(s):
    if not s:return None
    return datetime.fromisoformat(str(s).replace('Z','+00:00'))

def load(path):
    p=Path(path);txt=p.read_text(encoding='utf-8',errors='replace')
    if p.suffix.lower()=='.json':
        o=json.loads(txt);return o.get('events',o if isinstance(o,list) else [])
    out=[]
    for line in txt.splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def analyze(events,approved_trust_domains=None,approved_spiffe_ids=None):
    domains=set(approved_trust_domains or []);approved=set(approved_spiffe_ids or [])
    findings=[];timeline=[];by_process={};by_identity={}
    for e in sorted(events,key=lambda x:x.get('timestamp_utc') or ''):
        ts=dt(e.get('timestamp_utc'));sid=e.get('spiffe_id') or e.get('workload_identity')
        trust=e.get('trust_domain')
        if not trust and isinstance(sid,str) and sid.startswith('spiffe://'):
            trust=sid[len('spiffe://'):].split('/',1)[0]
        proc=e.get('process_id') or e.get('pid');host=e.get('host_id') or e.get('node_id')
        nb=dt(e.get('not_before_utc'));ex=dt(e.get('expires_utc'));rev=dt(e.get('revoked_utc'))
        status='VALID'
        if ts and nb and ts<nb:status='NOT_YET_VALID';findings.append({'type':'workload_identity_not_yet_valid','severity':'critical','spiffe_id':sid,'event':e})
        if ts and ex and ts>=ex:status='EXPIRED';findings.append({'type':'workload_identity_used_after_expiry','severity':'critical','spiffe_id':sid,'event':e})
        if ts and rev and ts>=rev:status='REVOKED';findings.append({'type':'workload_identity_used_after_revocation','severity':'critical','spiffe_id':sid,'event':e})
        if domains and trust not in domains:findings.append({'type':'unapproved_spiffe_trust_domain','severity':'critical','trust_domain':trust,'spiffe_id':sid})
        if approved and sid not in approved:findings.append({'type':'unapproved_workload_identity','severity':'critical','spiffe_id':sid})
        key=(host,proc)
        if sid and key!=(None,None):
            old=by_process.get(key)
            if old and old!=sid:findings.append({'type':'workload_identity_changed_for_process','severity':'critical','host_id':host,'process_id':proc,'previous':old,'current':sid})
            by_process[key]=sid
        if sid:
            rec=by_identity.setdefault(sid,{'hosts':set(),'processes':set(),'svid_fingerprints':set(),'events':0})
            if host:rec['hosts'].add(host)
            if proc is not None:rec['processes'].add(str(proc))
            if e.get('svid_sha256'):rec['svid_fingerprints'].add(e['svid_sha256'])
            rec['events']+=1
        selectors=e.get('selectors') or []
        expected=e.get('expected_selectors') or []
        if expected and not set(expected).issubset(set(selectors)):
            findings.append({'type':'workload_attestation_selector_mismatch','severity':'critical','spiffe_id':sid,'expected':expected,'observed':selectors})
        timeline.append({'timestamp_utc':e.get('timestamp_utc'),'spiffe_id':sid,'trust_domain':trust,'host_id':host,'process_id':proc,'status_at_event':status,'svid_sha256':e.get('svid_sha256'),'source':e.get('source')})
    serial={k:{'hosts':sorted(v['hosts']),'processes':sorted(v['processes']),'svid_fingerprints':sorted(v['svid_fingerprints']),'events':v['events']} for k,v in by_identity.items()}
    return {'schema':'ai-dfir/workload-identity/v1.4','identity_count':len(serial),'timeline':timeline,'identities':serial,'findings':findings,
            'rule':'Identity validity is evaluated at each event timestamp; current validity is not substituted for incident-time validity.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--events',required=True);ap.add_argument('--trust-domain',action='append',default=[]);ap.add_argument('--spiffe-id',action='append',default=[]);ap.add_argument('--out')
    a=ap.parse_args();o=analyze(load(a.events),a.trust_domain,a.spiffe_id);s=json.dumps(o,indent=2,sort_keys=True)
    Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
