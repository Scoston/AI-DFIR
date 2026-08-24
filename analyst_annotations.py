#!/usr/bin/env python3
"""Signed, chained analyst annotations stored separately from source evidence."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, uuid
from datetime import datetime, timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope


def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def canon(o):return json.dumps(o,sort_keys=True,separators=(',',':')).encode()


def last_hash(path):
    prev='0'*64
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():prev=json.loads(line)['record_hash']
    return prev


def add(path,private_key,case_id,author,note,evidence_ref=None,tags=None):
    prev=last_hash(path)
    payload={'schema':'ai-dfir/analyst-annotation/v0.7','annotation_id':str(uuid.uuid4()),
             'case_id':case_id,'timestamp_utc':utc(),'author':author,'note':note,
             'evidence_ref':evidence_ref,'tags':sorted(set(tags or [])),'prev_record_hash':prev}
    env=sign_payload(Path(private_key),payload)
    core={'envelope':env,'prev_record_hash':prev}
    rh=hashlib.sha256(canon(core)).hexdigest();record={**core,'record_hash':rh}
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a',encoding='utf-8') as f:
        f.write(json.dumps(record,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
    return record


def verify(path,public_key):
    prev='0'*64;count=0
    for no,line in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
        if not line.strip():continue
        r=json.loads(line);got=r['record_hash'];core={'envelope':r['envelope'],'prev_record_hash':r['prev_record_hash']}
        if r['prev_record_hash']!=prev:raise ValueError(f'chain mismatch line {no}')
        if hashlib.sha256(canon(core)).hexdigest()!=got:raise ValueError(f'record hash mismatch line {no}')
        p=verify_envelope(Path(public_key),r['envelope'])
        if p.get('prev_record_hash')!=prev:raise ValueError(f'signed payload chain mismatch line {no}')
        prev=got;count+=1
    return {'valid':True,'record_count':count,'last_record_hash':prev}


def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('add');p.add_argument('--log',required=True);p.add_argument('--private-key',required=True)
    p.add_argument('--case-id',required=True);p.add_argument('--author',required=True);p.add_argument('--note',required=True)
    p.add_argument('--evidence-ref');p.add_argument('--tag',action='append',default=[])
    p=sp.add_parser('verify');p.add_argument('--log',required=True);p.add_argument('--public-key',required=True)
    a=ap.parse_args()
    if a.cmd=='add':print(json.dumps(add(Path(a.log),a.private_key,a.case_id,a.author,a.note,a.evidence_ref,a.tag),indent=2,sort_keys=True))
    else:print(json.dumps(verify(Path(a.log),a.public_key),indent=2,sort_keys=True))

if __name__=='__main__':main()
