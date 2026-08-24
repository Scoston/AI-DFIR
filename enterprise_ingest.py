#!/usr/bin/env python3
"""Verify a distributed collector bundle and ingest it into the enterprise CAS repository."""
import argparse,json
from pathlib import Path
from collector_bundle import verify
from evidence_repository import Repository
from enterprise_case import CaseDB

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--bundle",required=True);ap.add_argument("--registry",required=True)
    ap.add_argument("--repository",required=True);ap.add_argument("--actor",required=True)
    ap.add_argument("--repository-key-hex");ap.add_argument("--retention-days",type=int);ap.add_argument("--cases-db",required=True)
    a=ap.parse_args()
    payload,findings=verify(a.bundle,a.registry)
    if findings:raise RuntimeError(f"bundle integrity failed: {findings}")
    case=CaseDB(a.cases_db).get(payload["case_id"])
    if not case:raise KeyError(f"case not found: {payload['case_id']}")
    if case.get("tenant_id") != payload.get("tenant_id"):
        raise PermissionError("collector bundle tenant does not match enterprise case tenant")
    repo=Repository(a.repository,bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
    root=Path(a.bundle);ingested=[]
    for x in payload["files"]:
        ingested.append(repo.add_file(
            payload["case_id"],root/x["relative_path"],x["logical_name"],a.actor,
            source=f"collector:{payload['collector_id']}",classification=x["classification"],
            retention_days=a.retention_days,
            metadata={"collector_bundle_id":payload["bundle_id"],"collector_id":payload["collector_id"],
                      "original_relative_path":x["relative_path"]}))
    print(json.dumps({"bundle_id":payload["bundle_id"],"case_id":payload["case_id"],
                      "ingested":ingested},indent=2,sort_keys=True))
if __name__=="__main__":main()
