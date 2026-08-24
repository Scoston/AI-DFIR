#!/usr/bin/env python3
"""
Signed forensic acquisition manifest v1.2.

The manifest binds artifact path/name, SHA-256, source attribution, time
coverage, clock quality and evidence flags. Verification writes a separate
trust record consumed by evidence_quality.py.

An `authoritative` flag is only a source claim until the manifest signature and
artifact hashes are verified.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, socket, stat
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(path,chunk=8*1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(chunk),b""):h.update(b)
    return h.hexdigest()
def describe(path,logical_name,case_root,source_type,host,user,agent,coverage_start,coverage_end,
             clock_offset_ms,clock_uncertainty_ms,authoritative,corroborated):
    p=Path(path);st=os.lstat(p);root=Path(case_root).resolve()
    try:rel=str(p.resolve().relative_to(root)).replace("\\","/")
    except Exception:rel=p.name
    return {"logical_name":logical_name,"relative_path":rel,"path":str(p.resolve()),
            "sha256":sha(p) if p.is_file() else None,"size":st.st_size,
            "source_type":source_type,"host":host,"user":user,"agent":agent,
            "coverage_start_utc":coverage_start,"coverage_end_utc":coverage_end,
            "clock_offset_ms":clock_offset_ms,"clock_uncertainty_ms":clock_uncertainty_ms,
            "authoritative":bool(authoritative),"corroborated":bool(corroborated),
            "inode":getattr(st,"st_ino",None),"device":getattr(st,"st_dev",None),
            "nlink":getattr(st,"st_nlink",None),"mode_octal":oct(stat.S_IMODE(st.st_mode)),
            "is_symlink":stat.S_ISLNK(st.st_mode),
            "symlink_target":os.readlink(p) if stat.S_ISLNK(st.st_mode) else None}
def create(args):
    arts=[]
    for spec in args.file:
        name,path=spec.split("=",1)
        arts.append(describe(path,name,args.case_root,args.source_type,args.source_host,args.source_user,args.source_agent,
                             args.coverage_start,args.coverage_end,args.clock_offset_ms,args.clock_uncertainty_ms,
                             args.authoritative,args.corroborated))
    payload={"schema":"ai-dfir/acquisition-manifest/v1.2","case_id":args.case_id,
             "acquired_utc":utc(),"collector_id":args.collector_id,"collector_host":socket.gethostname(),
             "platform":platform.platform(),"artifacts":arts,
             "clock_quality":{"offset_ms":args.clock_offset_ms,"uncertainty_ms":args.clock_uncertainty_ms}}
    env=sign_payload(Path(args.private_key),payload);Path(args.out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env
def verify(manifest,public_key,case_root,trust_out):
    env=json.loads(Path(manifest).read_text());payload=verify_envelope(Path(public_key),env)
    root=Path(case_root).resolve();findings=[];verified=[]
    for e in payload.get("artifacts",[]):
        candidates=[root/e.get("relative_path",""),root/Path(e.get("path","")).name]
        p=next((x for x in candidates if x.exists() and x.is_file()),None)
        if not p:
            findings.append({"type":"acquisition_artifact_missing","logical_name":e.get("logical_name")});continue
        got=sha(p)
        ok=got==e.get("sha256")
        verified.append({"logical_name":e.get("logical_name"),"relative_path":e.get("relative_path"),
                         "sha256":e.get("sha256"),"verified":ok})
        if not ok:findings.append({"type":"acquisition_artifact_hash_mismatch","path":str(p),"expected":e.get("sha256"),"actual":got})
    trust={"schema":"ai-dfir/acquisition-trust/v1.2","manifest_signature_verified":True,
           "manifest_file_sha256":sha(manifest),"collector_id":payload.get("collector_id"),
           "case_id":payload.get("case_id"),"artifact_verification":verified,
           "valid":not findings,"findings":findings}
    Path(trust_out).write_text(json.dumps(trust,indent=2,sort_keys=True))
    # Store only the verified payload for the Evidence Quality engine.
    (root/"ACQUISITION_MANIFEST.json").write_text(json.dumps(payload,indent=2,sort_keys=True))
    return trust
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("create");p.add_argument("--case-id",required=True);p.add_argument("--case-root",required=True)
    p.add_argument("--collector-id",required=True);p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    p.add_argument("--file",action="append",required=True,help="LOGICAL_NAME=PATH")
    p.add_argument("--source-type");p.add_argument("--source-host");p.add_argument("--source-user");p.add_argument("--source-agent")
    p.add_argument("--coverage-start");p.add_argument("--coverage-end");p.add_argument("--clock-offset-ms",type=float);p.add_argument("--clock-uncertainty-ms",type=float)
    p.add_argument("--authoritative",action="store_true");p.add_argument("--corroborated",action="store_true")
    p=sp.add_parser("verify");p.add_argument("--manifest",required=True);p.add_argument("--public-key",required=True);p.add_argument("--case-root",required=True);p.add_argument("--trust-out",required=True)
    a=ap.parse_args();obj=create(a) if a.cmd=="create" else verify(a.manifest,a.public_key,a.case_root,a.trust_out)
    print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=="__main__":main()
