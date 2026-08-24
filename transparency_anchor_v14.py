#!/usr/bin/env python3
"""Offline transparency-log submission bundle and receipt verification."""
from __future__ import annotations
import argparse,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def create(subjects,private_key,out,identity=None):
    subs=[{'name':Path(p).name,'path':str(Path(p).resolve()),'sha256':sha(p),'size':Path(p).stat().st_size} for p in subjects]
    payload={'schema':'ai-dfir/transparency-submission/v1.4','created_utc':utc(),'identity':identity,'subjects':subs,
             'intended_log':'rekor-compatible-or-private-transparency-log','network_submission_performed':False}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def verify_submission(path,public_key):return verify_envelope(Path(public_key),json.loads(Path(path).read_text()))

def verify_receipt(submission,public_key,receipt):
    p=verify_submission(submission,public_key);r=json.loads(Path(receipt).read_text());findings=[]
    expected={x['sha256'] for x in p['subjects']};observed=set(r.get('subject_sha256') or [])
    if not expected.issubset(observed):findings.append({'type':'transparency_receipt_subject_mismatch','severity':'critical','missing':sorted(expected-observed)})
    if not r.get('inclusion_verified',False):findings.append({'type':'transparency_inclusion_not_verified','severity':'critical'})
    if not r.get('log_id'):findings.append({'type':'transparency_log_id_missing','severity':'high'})
    return {'schema':'ai-dfir/transparency-receipt-validation/v1.4','valid':not findings,'submission':p,'receipt':r,'findings':findings,
            'rule':'AI-DFIR prepares and verifies evidence bundles but does not silently submit evidence to external logs.'}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--subject',action='append',required=True);p.add_argument('--private-key',required=True);p.add_argument('--identity');p.add_argument('--out',required=True)
    p=sp.add_parser('verify');p.add_argument('--submission',required=True);p.add_argument('--public-key',required=True)
    p=sp.add_parser('verify-receipt');p.add_argument('--submission',required=True);p.add_argument('--public-key',required=True);p.add_argument('--receipt',required=True);p.add_argument('--out')
    a=ap.parse_args()
    if a.cmd=='create':o=create(a.subject,a.private_key,a.out,a.identity)
    elif a.cmd=='verify':o={'valid':True,'payload':verify_submission(a.submission,a.public_key)}
    else:o=verify_receipt(a.submission,a.public_key,a.receipt)
    s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if getattr(a,'out',None) and a.cmd=='verify-receipt' else print(s)
if __name__=='__main__':main()
