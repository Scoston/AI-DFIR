#!/usr/bin/env python3
"""Signed distributed collector evidence bundles."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, uuid
from datetime import datetime, timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope, load_public, key_id

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(8*1024*1024),b""):h.update(b)
    return h.hexdigest()

def create(bundle_dir,collector_id,case_id,tenant_id,private_key,files):
    root=Path(bundle_dir);root.mkdir(parents=True,exist_ok=False);ev=root/"evidence";ev.mkdir()
    entries=[]
    for i,spec in enumerate(files):
        # NAME=PATH[:CLASSIFICATION] -- classification suffix is optional.
        name,raw=spec.split("=",1);classification="confidential"
        if "::" in raw:raw,classification=raw.rsplit("::",1)
        src=Path(raw);target=ev/f"{i:04d}_{src.name}";shutil.copy2(src,target)
        entries.append({"logical_name":name,"relative_path":str(target.relative_to(root)),
                        "sha256":sha(target),"size":target.stat().st_size,
                        "classification":classification})
    manifest={"schema":"ai-dfir/collector-bundle/v1.0","bundle_id":str(uuid.uuid4()),
              "collector_id":collector_id,"case_id":case_id,"tenant_id":tenant_id,"created_utc":utc(),"files":entries}
    env=sign_payload(Path(private_key),manifest)
    (root/"manifest.dsse-like.json").write_text(json.dumps(env,indent=2,sort_keys=True))
    return env

def verify(bundle_dir,registry_path):
    root=Path(bundle_dir);env=json.loads((root/"manifest.dsse-like.json").read_text())
    collector=env["payload"].get("collector_id")
    reg=json.loads(Path(registry_path).read_text())
    ent=reg.get("collectors",{}).get(collector)
    if not ent or not ent.get("enabled",True):raise PermissionError("collector not enrolled/enabled")
    allowed=set(ent.get("allowed_tenants") or [])
    tenant=env["payload"].get("tenant_id")
    if allowed and tenant not in allowed:raise PermissionError("collector not authorized for tenant")
    pub_path=root/"_collector_pub.pem";pub_path.write_text(ent["public_key_pem"])
    try:payload=verify_envelope(pub_path,env)
    finally:pub_path.unlink(missing_ok=True)
    findings=[]
    for x in payload["files"]:
        p=root/x["relative_path"]
        if not p.exists():findings.append({"type":"missing","path":x["relative_path"]});continue
        if p.stat().st_size!=x["size"]:findings.append({"type":"size","path":x["relative_path"]})
        if sha(p)!=x["sha256"]:findings.append({"type":"sha256","path":x["relative_path"]})
    return payload,findings

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("create");p.add_argument("--out",required=True);p.add_argument("--collector-id",required=True);p.add_argument("--case-id",required=True);p.add_argument("--tenant-id",required=True);p.add_argument("--private-key",required=True);p.add_argument("--file",action="append",required=True)
    p=sp.add_parser("verify");p.add_argument("--bundle",required=True);p.add_argument("--registry",required=True)
    a=ap.parse_args()
    if a.cmd=="create":print(json.dumps(create(a.out,a.collector_id,a.case_id,a.tenant_id,a.private_key,a.file),indent=2,sort_keys=True))
    else:
        payload,findings=verify(a.bundle,a.registry);print(json.dumps({"valid":not findings,"payload":payload,"findings":findings},indent=2,sort_keys=True));raise SystemExit(0 if not findings else 2)
if __name__=="__main__":main()
