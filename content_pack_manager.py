#!/usr/bin/env python3
"""Build and verify signed AI-DFIR detection/evidence content releases."""
from __future__ import annotations
import argparse, hashlib, json, shutil, tempfile
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope

HERE=Path(__file__).resolve().parent
INCLUDE=[
 "evidence_packs","agentic_detection_rules.json","AGENTIC_THREAT_CROSSWALK.json",
 "MICROSOFT_AGENTIC_CROSSWALK.json","MICROSOFT_AI_ALERT_CATALOG.json",
 "provider_adapters.json","EVIDENCE_PACK_SCHEMA.md","EVIDENCE_PACK_SCHEMA_V1.1.md","execution_integrity_rules.json","representation_integrity_rules.json","a2a_trust_rules.json","runtime_trust_rules.json","enterprise_v15_rules.json"
]
def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()

def build(out,private_key,version):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);content=out/"content";content.mkdir()
    files=[]
    for rel in INCLUDE:
        src=HERE/rel
        if not src.exists():continue
        dst=content/rel
        if src.is_dir():shutil.copytree(src,dst)
        else:dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
    for p in sorted(content.rglob("*")):
        if p.is_file():files.append({"path":str(p.relative_to(out)),"sha256":sha(p),"size":p.stat().st_size})
    manifest={"schema":"ai-dfir/content-release/v1.5","version":version,"created_utc":utc(),"files":files}
    env=sign_payload(Path(private_key),manifest)
    (out/"CONTENT_RELEASE.json").write_text(json.dumps(env,indent=2,sort_keys=True))
    return env

def verify(out,public_key):
    out=Path(out);env=json.loads((out/"CONTENT_RELEASE.json").read_text())
    m=verify_envelope(Path(public_key),env);findings=[]
    for f in m["files"]:
        p=out/f["path"]
        if not p.exists():findings.append({"type":"missing","path":f["path"]});continue
        if p.stat().st_size!=f["size"]:findings.append({"type":"size","path":f["path"]})
        if sha(p)!=f["sha256"]:findings.append({"type":"sha256","path":f["path"]})
    return m,findings

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("build");p.add_argument("--out",required=True);p.add_argument("--private-key",required=True);p.add_argument("--version",required=True)
    p=sp.add_parser("verify");p.add_argument("--release",required=True);p.add_argument("--public-key",required=True)
    a=ap.parse_args()
    if a.cmd=="build":print(json.dumps(build(a.out,a.private_key,a.version),indent=2,sort_keys=True))
    else:
        m,f=verify(a.release,a.public_key);print(json.dumps({"valid":not f,"manifest":m,"findings":f},indent=2,sort_keys=True));raise SystemExit(0 if not f else 2)
if __name__=="__main__":main()
