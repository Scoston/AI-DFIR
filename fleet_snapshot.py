#!/usr/bin/env python3
"""
Create a lightweight signed incident snapshot from fleet-node evidence.

Large model directories should be represented by manifests/hashes rather than
copied into every alert snapshot.
"""
import argparse, subprocess, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case-id",required=True)
    ap.add_argument("--node-id",required=True)
    ap.add_argument("--seq",required=True)
    ap.add_argument("--private-key",required=True)
    ap.add_argument("--artifact",action="append",default=[],help="NAME=PATH")
    ap.add_argument("--material",action="append",default=[],help="NAME=PATH")
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    cmd=[sys.executable,str(HERE/"provenance_bundle.py"),"bundle",
         "--case-id",args.case_id,
         "--inference-id",f"fleet-{args.node_id}-seq-{args.seq}",
         "--private-key",args.private_key,
         "--host",args.node_id,
         "--no-copy",
         "--out",args.out]
    for x in args.artifact:cmd += ["--artifact",x]
    for x in args.material:cmd += ["--material",x]
    subprocess.run(cmd,check=True)


if __name__=="__main__":main()
