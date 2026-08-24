#!/usr/bin/env python3
"""Prompt/context/RAG/tool-result/MCP catalog cache forensics."""
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime,timezone
from pathlib import Path

def parse_time(s):
    if not s:return None
    try:return datetime.fromisoformat(str(s).replace("Z","+00:00"))
    except Exception:return None

def analyze(records,source_manifest=None,now=None):
    now=now or datetime.now(timezone.utc);sources=source_manifest or {}
    findings=[];keys={}
    for r in records:
        key=r.get("cache_key");tenant=r.get("tenant_id");writer=r.get("writer")
        k=(r.get("cache_type"),key)
        if k in keys and keys[k].get("tenant_id")!=tenant:
            findings.append({"type":"cross_tenant_cache_key_reuse","severity":"critical",
                             "cache_type":r.get("cache_type"),"cache_key":key,
                             "tenants":[keys[k].get("tenant_id"),tenant]})
        keys[k]=r
        if r.get("writer_trust")=="untrusted":
            findings.append({"type":"cache_written_by_untrusted_source","severity":"high","record":r})
        expires=parse_time(r.get("expires_utc"))
        if r.get("event")=="read" and expires and expires<now:
            findings.append({"type":"expired_cache_entry_read","severity":"high","record":r})
        src_hashes=r.get("source_hashes") or []
        current=[sources.get(x) for x in r.get("source_ids") or []]
        current=[x for x in current if x]
        if current and sorted(src_hashes)!=sorted(current):
            findings.append({"type":"cache_source_hash_stale","severity":"high","record":r,"current_source_hashes":current})
        expected=r.get("expected_content_sha256")
        if expected and r.get("content_sha256")!=expected:
            findings.append({"type":"cache_content_mismatch","severity":"critical","record":r})
        if r.get("invalidated_utc") and r.get("event")=="read":
            findings.append({"type":"invalidated_cache_entry_reused","severity":"critical","record":r})
    return {"schema":"ai-dfir/cache-analysis/v1.1","records":len(records),"findings":findings}

def load_records(path):
    p=Path(path)
    if p.suffix.lower()==".json":
        obj=json.loads(p.read_text());return obj.get("records",obj if isinstance(obj,list) else [])
    out=[]
    for line in p.read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--records",required=True);ap.add_argument("--source-manifest");ap.add_argument("--out")
    a=ap.parse_args();sources=json.loads(Path(a.source_manifest).read_text()) if a.source_manifest else {}
    obj=analyze(load_records(a.records),sources);txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
