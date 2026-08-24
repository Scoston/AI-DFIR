#!/usr/bin/env python3
"""Session-history integrity checkpoints for resumable AI-agent state."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope
def line_hashes(path):
    out=[]
    for i,line in enumerate(Path(path).read_bytes().splitlines(),1):
        if line.strip():out.append({"line":i,"sha256":hashlib.sha256(line).hexdigest(),"length":len(line)})
    return out
def checkpoint(path,private_key,out):
    rows=line_hashes(path)
    payload={"schema":"ai-dfir/session-state-checkpoint/v1.2","path_name":Path(path).name,
             "line_count":len(rows),"line_hashes":rows,
             "file_sha256":hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def compare(path,checkpoint_file,public_key):
    env=json.loads(Path(checkpoint_file).read_text());base=verify_envelope(Path(public_key),env)
    cur=line_hashes(path);b=[x["sha256"] for x in base["line_hashes"]];c=[x["sha256"] for x in cur]
    prefix=0
    for x,y in zip(b,c):
        if x!=y:break
        prefix+=1
    findings=[]
    if b!=c:
        findings.append({"type":"session_history_integrity_divergence","severity":"critical",
                         "common_prefix_lines":prefix,"baseline_lines":len(b),"current_lines":len(c)})
    # Changed/fabricated approval semantics are triage leads, not proof.
    changed_lines=Path(path).read_text(encoding="utf-8",errors="replace").splitlines()[prefix:]
    consent=[]
    for i,line in enumerate(changed_lines,prefix+1):
        l=line.lower()
        if any(k in l for k in ("approved","authorized","permission granted","consent","autoapprove")):
            consent.append({"line":i,"sha256":hashlib.sha256(line.encode()).hexdigest()})
    if consent:findings.append({"type":"authorization_semantics_after_history_divergence","severity":"critical","records":consent[:50]})
    return {"schema":"ai-dfir/session-state-integrity/v1.2","baseline":base,"current_line_count":len(c),"findings":findings}
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("checkpoint");p.add_argument("--session",required=True);p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("verify");p.add_argument("--session",required=True);p.add_argument("--checkpoint",required=True);p.add_argument("--public-key",required=True);p.add_argument("--out")
    a=ap.parse_args()
    obj=checkpoint(a.session,a.private_key,a.out) if a.cmd=="checkpoint" else compare(a.session,a.checkpoint,a.public_key)
    if a.cmd=="checkpoint":print(json.dumps(obj,indent=2,sort_keys=True))
    else:
        s=json.dumps(obj,indent=2,sort_keys=True)
        if a.out:Path(a.out).write_text(s)
        else:print(s)
if __name__=="__main__":main()
