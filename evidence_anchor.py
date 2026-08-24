#!/usr/bin/env python3
"""
Signed repository anchor for external/WORM timestamping.

The anchor binds:
- audit-chain head at a specific event count
- all repository object SHA-256 values present at anchor time
- a deterministic Merkle root over those leaves

The anchor file can be copied to a separate SIEM, object-lock bucket, or
timestamping system. This tool does not transmit evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, sqlite3
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def h(x):return hashlib.sha256(x).digest()

def merkle_hex(leaves):
    nodes=[h(x.encode()) for x in sorted(leaves)]
    if not nodes:return hashlib.sha256(b"").hexdigest()
    while len(nodes)>1:
        if len(nodes)%2:nodes.append(nodes[-1])
        nodes=[h(nodes[i]+nodes[i+1]) for i in range(0,len(nodes),2)]
    return nodes[0].hex()

def audit_at(path,count=None):
    hashes=[]
    p=Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():continue
            hashes.append(json.loads(line)["event_hash"])
    if count is not None:hashes=hashes[:count]
    return (hashes[-1] if hashes else "0"*64,len(hashes),hashes)

def object_digests(repo):
    db=Path(repo)/"repository.db"
    c=sqlite3.connect(db)
    try:return sorted(r[0] for r in c.execute("SELECT sha256 FROM objects"))
    finally:c.close()

def create(repo,private_key,out):
    repo=Path(repo).resolve()
    head,count,audits=audit_at(repo/"repository_audit.jsonl")
    objects=object_digests(repo)
    leaves=["audit:"+x for x in audits]+["object:"+x for x in objects]
    payload={"schema":"ai-dfir/repository-anchor/v1.1","created_utc":utc(),
             "audit_event_count":count,"audit_head":head,"object_count":len(objects),
             "object_digests":objects,"merkle_root":merkle_hex(leaves)}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def verify(anchor,public_key,repo=None):
    env=json.loads(Path(anchor).read_text());p=verify_envelope(Path(public_key),env);findings=[]
    leaves=["object:"+x for x in p.get("object_digests",[])]
    if repo:
        repo=Path(repo)
        head,count,audits=audit_at(repo/"repository_audit.jsonl",p["audit_event_count"])
        leaves += ["audit:"+x for x in audits]
        if count!=p["audit_event_count"] or head!=p["audit_head"]:
            findings.append({"type":"audit_anchor_mismatch","expected_head":p["audit_head"],"actual_head":head})
        current=set(object_digests(repo));missing=sorted(set(p.get("object_digests",[]))-current)
        if missing:findings.append({"type":"anchored_objects_missing","sha256":missing})
    else:
        # Without a repository only signature/payload structure can be verified.
        findings.append({"type":"repository_not_supplied","severity":"informational"})
        return p,findings
    root=merkle_hex(leaves)
    if root!=p["merkle_root"]:findings.append({"type":"merkle_root_mismatch","expected":p["merkle_root"],"actual":root})
    return p,findings

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("create");p.add_argument("--repository",required=True);p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("verify");p.add_argument("--anchor",required=True);p.add_argument("--public-key",required=True);p.add_argument("--repository")
    a=ap.parse_args()
    if a.cmd=="create":print(json.dumps(create(a.repository,a.private_key,a.out),indent=2,sort_keys=True))
    else:
        payload,findings=verify(a.anchor,a.public_key,a.repository)
        print(json.dumps({"valid":not [x for x in findings if x.get("severity")!="informational"],"payload":payload,"findings":findings},indent=2,sort_keys=True))
        if any(x.get("severity")!="informational" for x in findings):raise SystemExit(2)
if __name__=="__main__":main()
