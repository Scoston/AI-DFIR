#!/usr/bin/env python3
"""Create/verify a signed repository integrity checkpoint for external anchoring."""
import argparse,hashlib,json
from pathlib import Path
from datetime import datetime,timezone
from evidence_repository import Repository
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def audit_head(path):
    head="0"*64;count=0
    p=Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            if line.strip():head=json.loads(line)["event_hash"];count+=1
    return head,count
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("create");p.add_argument("--repository",required=True);p.add_argument("--private-key",required=True);p.add_argument("--out",required=True);p.add_argument("--repository-key-hex")
    p=sp.add_parser("verify");p.add_argument("--checkpoint",required=True);p.add_argument("--public-key",required=True)
    a=ap.parse_args()
    if a.cmd=="create":
        repo=Repository(a.repository,bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
        integrity=repo.verify();head,count=audit_head(repo.audit_path)
        payload={"schema":"ai-dfir/repository-checkpoint/v1.0","created_utc":utc(),
                 "repository":str(repo.root),"audit_head":head,"audit_event_count":count,
                 "repository_integrity":integrity}
        env=sign_payload(Path(a.private_key),payload);Path(a.out).write_text(json.dumps(env,indent=2,sort_keys=True));print(json.dumps(env,indent=2,sort_keys=True))
    else:
        env=json.loads(Path(a.checkpoint).read_text());payload=verify_envelope(Path(a.public_key),env);print(json.dumps({"valid":True,"payload":payload},indent=2,sort_keys=True))
if __name__=="__main__":main()
