#!/usr/bin/env python3
"""Materialize a repository case into a read-only analyst workspace."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil
from pathlib import Path
from evidence_repository import Repository
from enterprise_case import CaseDB
from enterprise_rbac import can_read_classification

def safe(s):
    s=re.sub(r"[^A-Za-z0-9._/-]+","_",s).strip("/")
    return s or "artifact"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repository",required=True);ap.add_argument("--case-id",required=True)
    ap.add_argument("--out",required=True);ap.add_argument("--actor",required=True);ap.add_argument("--role",required=True)
    ap.add_argument("--repository-key-hex");ap.add_argument("--cases-db")
    a=ap.parse_args();repo=Repository(a.repository,bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
    out=Path(a.out).resolve()
    if out.exists():raise FileExistsError(out)
    out.mkdir(parents=True)
    manifest=[]
    used=set()
    for e in repo.list_case(a.case_id):
        if not can_read_classification(a.role,e["classification"]):continue
        rel=(e.get("metadata") or {}).get("workspace_path") or e["logical_name"]
        rel=safe(rel)
        base=rel;n=1
        while rel in used:
            p=Path(base);rel=str(p.with_name(p.stem+f"_{n}"+p.suffix));n+=1
        used.add(rel)
        target=out/rel;repo.extract(e["evidence_id"],target,a.actor)
        os.chmod(target,0o440)
        manifest.append({"evidence_id":e["evidence_id"],"logical_name":e["logical_name"],
                         "workspace_path":rel,"sha256":e["sha256"],"classification":e["classification"],
                         "source":e["source"]})
    if a.cases_db:
        case=CaseDB(a.cases_db).get(a.case_id)
        if case:(out/"case.json").write_text(json.dumps({
            "case_id":case["case_id"],"created_utc":case["created_utc"],"tool_version":"1.0",
            "enterprise_case":case
        },indent=2,sort_keys=True))
    (out/"REPOSITORY_EXPORT_MANIFEST.json").write_text(json.dumps({
        "schema":"ai-dfir/repository-export/v1.0","case_id":a.case_id,"evidence":manifest
    },indent=2,sort_keys=True))
    # Files are read-only; directory remains writable only for derived analyst output if copied elsewhere.
    print(json.dumps({"case_id":a.case_id,"out":str(out),"evidence_count":len(manifest)},indent=2))
if __name__=="__main__":main()
