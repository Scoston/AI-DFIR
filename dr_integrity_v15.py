#!/usr/bin/env python3
"""Disaster-recovery manifest and restore validation for AI-DFIR evidence."""
from __future__ import annotations
import argparse,hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def inventory(root):
    root=Path(root).resolve();items=[]
    for p in sorted(root.rglob('*')):
        if p.is_file():items.append({'path':str(p.relative_to(root)),'sha256':sha(p),'size':p.stat().st_size})
    return items
def create(root,backup_id,private_key,out):
    items=inventory(root);payload={'schema':'ai-dfir/dr-backup-manifest/v1.5','backup_id':backup_id,'created_utc':utc(),'root_name':Path(root).name,'file_count':len(items),'files':items}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def validate(restored_root,manifest,public_key):
    expected=verify_envelope(Path(public_key),json.loads(Path(manifest).read_text()));actual={x['path']:x for x in inventory(restored_root)};findings=[]
    for e in expected['files']:
        a=actual.get(e['path'])
        if not a:findings.append({'type':'restore_file_missing','severity':'critical','path':e['path']})
        elif a['sha256']!=e['sha256']:findings.append({'type':'restore_hash_mismatch','severity':'critical','path':e['path'],'expected':e['sha256'],'actual':a['sha256']})
    extras=sorted(set(actual)-{x['path'] for x in expected['files']})
    if extras:findings.append({'type':'restore_extra_files','severity':'medium','count':len(extras),'examples':extras[:20]})
    return {'schema':'ai-dfir/dr-restore-validation/v1.5','backup_id':expected['backup_id'],'validated_utc':utc(),'valid':not any(x['severity']=='critical' for x in findings),'expected_files':len(expected['files']),'actual_files':len(actual),'findings':findings}
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--root',required=True);p.add_argument('--backup-id',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('validate');p.add_argument('--restored-root',required=True);p.add_argument('--manifest',required=True);p.add_argument('--public-key',required=True);p.add_argument('--out')
    a=ap.parse_args();obj=create(a.root,a.backup_id,a.private_key,a.out) if a.cmd=='create' else validate(a.restored_root,a.manifest,a.public_key);txt=json.dumps(obj,indent=2,sort_keys=True);Path(a.out).write_text(txt) if a.cmd=='validate' and a.out else print(txt)
if __name__=='__main__':main()
