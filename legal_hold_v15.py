#!/usr/bin/env python3
"""Signed legal-hold lifecycle records; release is a separate signed event."""
from __future__ import annotations
import argparse,json,uuid
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def create(case_id,tenant_id,reason,actor,private_key,out):
    payload={'schema':'ai-dfir/legal-hold/v1.5','hold_id':'HOLD-'+uuid.uuid4().hex,'tenant_id':tenant_id,'case_id':case_id,'status':'ACTIVE','reason':reason,'created_by':actor,'created_utc':utc()}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def release(hold_file,hold_public_key,actor,reason,private_key,out):
    hold=verify_envelope(Path(hold_public_key),json.loads(Path(hold_file).read_text()))
    if hold.get('status')!='ACTIVE':raise ValueError('hold not active')
    payload={'schema':'ai-dfir/legal-hold-release/v1.5','hold_id':hold['hold_id'],'tenant_id':hold['tenant_id'],'case_id':hold['case_id'],'status':'RELEASED','released_by':actor,'released_utc':utc(),'reason':reason,'hold_sha256':__import__('hashlib').sha256(Path(hold_file).read_bytes()).hexdigest()}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def validate(hold_file,hold_public_key,release_file=None,release_public_key=None):
    import hashlib
    findings=[]
    try:hold=verify_envelope(Path(hold_public_key),json.loads(Path(hold_file).read_text()))
    except Exception as e:return {'schema':'ai-dfir/legal-hold-validation/v1.5','valid':False,'findings':[{'type':'legal_hold_signature_invalid','severity':'critical','error':repr(e)}]}
    state='ACTIVE';release_payload=None
    if release_file:
        try:release_payload=verify_envelope(Path(release_public_key or hold_public_key),json.loads(Path(release_file).read_text()))
        except Exception as e:findings.append({'type':'legal_hold_release_signature_invalid','severity':'critical','error':repr(e)});release_payload=None
        if release_payload:
            if release_payload.get('hold_id')!=hold.get('hold_id') or release_payload.get('tenant_id')!=hold.get('tenant_id') or release_payload.get('case_id')!=hold.get('case_id'):
                findings.append({'type':'legal_hold_release_binding_mismatch','severity':'critical'})
            expected=hashlib.sha256(Path(hold_file).read_bytes()).hexdigest()
            if release_payload.get('hold_sha256')!=expected:findings.append({'type':'legal_hold_release_hash_mismatch','severity':'critical'})
            if not findings:state='RELEASED'
    return {'schema':'ai-dfir/legal-hold-validation/v1.5','valid':not any(x['severity']=='critical' for x in findings),'state':state,'hold_id':hold.get('hold_id'),'tenant_id':hold.get('tenant_id'),'case_id':hold.get('case_id'),'findings':findings}
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--case',required=True);p.add_argument('--tenant',required=True);p.add_argument('--reason',required=True);p.add_argument('--actor',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('release');p.add_argument('--hold',required=True);p.add_argument('--hold-public-key',required=True);p.add_argument('--actor',required=True);p.add_argument('--reason',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('validate');p.add_argument('--hold',required=True);p.add_argument('--hold-public-key',required=True);p.add_argument('--release');p.add_argument('--release-public-key');p.add_argument('--out')
    a=ap.parse_args()
    if a.cmd=='create':obj=create(a.case,a.tenant,a.reason,a.actor,a.private_key,a.out)
    elif a.cmd=='release':obj=release(a.hold,a.hold_public_key,a.actor,a.reason,a.private_key,a.out)
    else:obj=validate(a.hold,a.hold_public_key,a.release,a.release_public_key)
    txt=json.dumps(obj,indent=2,sort_keys=True);Path(a.out).write_text(txt) if a.cmd=='validate' and a.out else print(txt)
if __name__=='__main__':main()
