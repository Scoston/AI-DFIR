#!/usr/bin/env python3
"""Distributed collector identity registry."""
import argparse,json
from pathlib import Path
from fleet_crypto import load_public,key_id

def load(p):
    path=Path(p)
    return json.loads(path.read_text()) if path.exists() else {"schema":"ai-dfir/collector-registry/v1.0","collectors":{}}
def save(p,o):Path(p).parent.mkdir(parents=True,exist_ok=True);Path(p).write_text(json.dumps(o,indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("init");p.add_argument("--registry",required=True)
    p=sp.add_parser("enroll");p.add_argument("--registry",required=True);p.add_argument("--collector-id",required=True);p.add_argument("--public-key",required=True);p.add_argument("--tenant",action="append",default=[])
    p=sp.add_parser("disable");p.add_argument("--registry",required=True);p.add_argument("--collector-id",required=True)
    a=ap.parse_args()
    if a.cmd=="init":save(a.registry,load(a.registry));return
    r=load(a.registry)
    if a.cmd=="enroll":
        pub=load_public(Path(a.public_key))
        r["collectors"][a.collector_id]={"key_id":key_id(pub),"public_key_pem":Path(a.public_key).read_text(),"enabled":True,"allowed_tenants":sorted(set(a.tenant))}
    else:r["collectors"][a.collector_id]["enabled"]=False
    save(a.registry,r);print(json.dumps(r["collectors"].get(a.collector_id),indent=2,sort_keys=True))
if __name__=="__main__":main()
