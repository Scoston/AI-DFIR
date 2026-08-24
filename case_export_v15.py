#!/usr/bin/env python3
"""Tenant-scoped signed case export and independent export verification."""
from __future__ import annotations
import argparse,hashlib,json,tempfile,zipfile
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()
def safe_member(name):
    p=PurePosixPath(name)
    return not p.is_absolute() and '..' not in p.parts and '\\' not in name

def export_case(case_root,tenant_id,case_id,private_key,out_zip,include_evidence=False):
    root=Path(case_root).resolve();mp=(root/'00_case'/'case.json') if (root/'00_case'/'case.json').exists() else root/'case.json';meta=json.loads(mp.read_text())
    if meta.get('case_id')!=case_id:raise ValueError('case ID mismatch')
    if meta.get('tenant_id') not in (None,tenant_id):raise PermissionError('tenant mismatch')
    files=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or '__pycache__' in p.parts:continue
        rel=str(p.relative_to(root)).replace('\\','/')
        if not include_evidence and any(x in rel for x in ('02_checkpoint','04_activations','17_representation_intake')):continue
        files.append({'path':rel,'sha256':sha(p),'size':p.stat().st_size})
    payload={'schema':'ai-dfir/case-export-manifest/v1.5','tenant_id':tenant_id,'case_id':case_id,'created_utc':utc(),'include_evidence':include_evidence,'files':files}
    env=sign_payload(Path(private_key),payload);out=Path(out_zip);out.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for f in files:z.write(root/f['path'],arcname=f['path'])
        z.writestr('CASE_EXPORT_MANIFEST.signed.json',json.dumps(env,indent=2,sort_keys=True))
    return {'schema':'ai-dfir/case-export/v1.5','zip':str(out),'sha256':sha(out),'file_count':len(files),'tenant_id':tenant_id,'case_id':case_id,'created_utc':utc()}

def verify_export(zip_path,public_key,expected_tenant=None,expected_case=None):
    findings=[];zp=Path(zip_path)
    with zipfile.ZipFile(zp) as z:
        names=z.namelist()
        unsafe=[n for n in names if not safe_member(n)]
        if unsafe:findings.append({'type':'case_export_unsafe_member_path','severity':'critical','members':unsafe[:50]})
        if 'CASE_EXPORT_MANIFEST.signed.json' not in names:
            return {'schema':'ai-dfir/case-export-validation/v1.5','valid':False,'zip_sha256':sha(zp),'findings':[{'type':'case_export_manifest_missing','severity':'critical'}]}
        env=json.loads(z.read('CASE_EXPORT_MANIFEST.signed.json'))
        try:payload=verify_envelope(Path(public_key),env)
        except Exception as e:return {'schema':'ai-dfir/case-export-validation/v1.5','valid':False,'zip_sha256':sha(zp),'findings':[{'type':'case_export_signature_invalid','severity':'critical','error':repr(e)}]}
        if expected_tenant and payload.get('tenant_id')!=expected_tenant:findings.append({'type':'case_export_tenant_mismatch','severity':'critical'})
        if expected_case and payload.get('case_id')!=expected_case:findings.append({'type':'case_export_case_mismatch','severity':'critical'})
        expected={x['path']:x for x in payload.get('files') or []}
        actual={n for n in names if n!='CASE_EXPORT_MANIFEST.signed.json'}
        for rel,e in expected.items():
            if rel not in actual:findings.append({'type':'case_export_file_missing','severity':'critical','path':rel});continue
            raw=z.read(rel);got=hashlib.sha256(raw).hexdigest()
            if got!=e.get('sha256'):findings.append({'type':'case_export_hash_mismatch','severity':'critical','path':rel,'expected':e.get('sha256'),'actual':got})
            if len(raw)!=int(e.get('size',-1)):findings.append({'type':'case_export_size_mismatch','severity':'critical','path':rel})
        extras=sorted(actual-set(expected))
        if extras:findings.append({'type':'case_export_unmanifested_files','severity':'critical','files':extras[:50]})
    return {'schema':'ai-dfir/case-export-validation/v1.5','valid':not any(x['severity']=='critical' for x in findings),'validated_utc':utc(),'zip_sha256':sha(zp),'tenant_id':payload.get('tenant_id'),'case_id':payload.get('case_id'),'file_count':len(expected),'findings':findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--case-root',required=True);p.add_argument('--tenant',required=True);p.add_argument('--case',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True);p.add_argument('--include-evidence',action='store_true')
    p=sp.add_parser('verify');p.add_argument('--zip',required=True);p.add_argument('--public-key',required=True);p.add_argument('--tenant');p.add_argument('--case');p.add_argument('--out')
    a=ap.parse_args()
    if a.cmd=='create':obj=export_case(a.case_root,a.tenant,a.case,a.private_key,a.out,a.include_evidence)
    else:obj=verify_export(a.zip,a.public_key,a.tenant,a.case)
    txt=json.dumps(obj,indent=2,sort_keys=True);Path(a.out).write_text(txt) if a.cmd=='verify' and a.out else print(txt)
    if a.cmd=='verify' and not obj['valid']:raise SystemExit(2)
if __name__=='__main__':main()
