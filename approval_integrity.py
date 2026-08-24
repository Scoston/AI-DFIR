#!/usr/bin/env python3
"""Detect approval/trust decisions bound to a path/name while content changed later."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()
def analyze(records):
    findings=[];rows=[]
    for r in records:
        path=Path(r["resource_path"])
        cur=None;real=None
        if path.exists() or path.is_symlink():
            real=os.path.realpath(path)
            if path.is_file():cur=sha(path)
        row={**r,"current_sha256":cur,"current_realpath":real};rows.append(row)
        approved=r.get("approved_sha256")
        if r.get("approval_scope") in ("path","name") and approved and cur and approved!=cur:
            findings.append({"type":"approval_toctou_content_changed","severity":"critical","record":row})
        if r.get("approved_realpath") and real and os.path.realpath(r["approved_realpath"])!=real:
            findings.append({"type":"approval_target_changed_via_path_resolution","severity":"critical","record":row})
        if not approved:
            findings.append({"type":"approval_not_bound_to_content_hash","severity":"high","record":row})
    return {"schema":"ai-dfir/approval-integrity-analysis/v1.2","records":rows,"findings":findings}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--records",required=True);ap.add_argument("--out")
    a=ap.parse_args();o=json.loads(Path(a.records).read_text());rows=o.get("records",o)
    obj=analyze(rows);s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
