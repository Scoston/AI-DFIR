#!/usr/bin/env python3
"""Signed/hash-chained analyst action audit overlay for enterprise cases."""
from __future__ import annotations
import argparse,hashlib,json,os,uuid
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def canon(o):return json.dumps(o,sort_keys=True,separators=(',',':')).encode()
def add(log,private_key,case_id,actor,action,object_ref=None,reason=None):
    log=Path(log);prev='0'*64
    if log.exists():
        for line in log.read_text().splitlines():
            if line.strip():prev=json.loads(line)['record_hash']
    payload={'schema':'ai-dfir/analyst-action/v1.4','action_id':'ACT-'+uuid.uuid4().hex,'timestamp_utc':utc(),'case_id':case_id,'actor':actor,'action':action,'object_ref':object_ref,'reason':reason,'prev_record_hash':prev}
    env=sign_payload(Path(private_key),payload);record={'envelope':env};record['record_hash']=hashlib.sha256(canon(record)).hexdigest()
    with log.open('a') as f:f.write(json.dumps(record,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
    return record

def verify(log,public_keys):
    keys=[Path(x) for x in public_keys];prev='0'*64;findings=[];count=0
    for n,line in enumerate(Path(log).read_text().splitlines(),1):
        if not line.strip():continue
        r=json.loads(line);rh=r.pop('record_hash');expected=hashlib.sha256(canon(r)).hexdigest()
        if rh!=expected:findings.append({'type':'analyst_audit_record_hash_mismatch','severity':'critical','line':n});break
        env=r['envelope'];payload=env.get('payload',{})
        if payload.get('prev_record_hash')!=prev:findings.append({'type':'analyst_audit_chain_break','severity':'critical','line':n});break
        ok=False
        for k in keys:
            try:verify_envelope(k,env);ok=True;break
            except Exception:pass
        if not ok:findings.append({'type':'analyst_audit_signature_untrusted','severity':'critical','line':n})
        prev=rh;count+=1
    return {'schema':'ai-dfir/analyst-action-audit/v1.4','valid':not findings,'records':count,'findings':findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('add');p.add_argument('--log',required=True);p.add_argument('--private-key',required=True);p.add_argument('--case-id',required=True);p.add_argument('--actor',required=True);p.add_argument('--action',required=True);p.add_argument('--object-ref');p.add_argument('--reason')
    p=sp.add_parser('verify');p.add_argument('--log',required=True);p.add_argument('--public-key',action='append',required=True)
    a=ap.parse_args();o=add(a.log,a.private_key,a.case_id,a.actor,a.action,a.object_ref,a.reason) if a.cmd=='add' else verify(a.log,a.public_key);print(json.dumps(o,indent=2,sort_keys=True))
if __name__=='__main__':main()
