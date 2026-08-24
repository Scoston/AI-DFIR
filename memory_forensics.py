#!/usr/bin/env python3
"""Persistent agent memory lineage, poisoning indicators, and cross-session fan-out."""
from __future__ import annotations
import argparse, json
from collections import defaultdict, deque
from pathlib import Path

def load_events(p):
    rows=[]
    for line in Path(p).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:rows.append(json.loads(line))
            except Exception:pass
    return rows

def analyze(events, trusted_writers=None):
    trusted=set(trusted_writers or [])
    writes={}
    reads=defaultdict(list)
    findings=[]
    for e in events:
        et=e.get("event_type");meta=e.get("metadata") or {}
        mid=meta.get("memory_id") or e.get("target_id")
        if et in ("memory_write","memory_update") and mid:
            writes[mid]=e
            if trusted and e.get("actor_id") not in trusted:
                findings.append({"type":"memory_untrusted_writer","severity":"high",
                                 "memory_id":mid,"writer":e.get("actor_id"),"event_id":e.get("event_id")})
            if not (meta.get("source_event_id") or e.get("cause_event_ids")):
                findings.append({"type":"memory_missing_provenance","severity":"medium",
                                 "memory_id":mid,"event_id":e.get("event_id")})
        elif et=="memory_read" and mid:
            reads[mid].append(e)

    lineage=[]
    cross_session=[]
    for mid,w in writes.items():
        wsession=w.get("session_id")
        rs=reads.get(mid,[])
        sessions=sorted(set(r.get("session_id") for r in rs if r.get("session_id")))
        lineage.append({
            "memory_id":mid,"write_event_id":w.get("event_id"),"writer":w.get("actor_id"),
            "write_session_id":wsession,"read_count":len(rs),"read_sessions":sessions,
            "content_sha256":w.get("content_sha256"),
        })
        other=[s for s in sessions if s!=wsession]
        if other:
            cross_session.append({"memory_id":mid,"write_session":wsession,
                                  "read_sessions":other,"fanout":len(other)})
            if len(other)>=2:
                findings.append({"type":"memory_cross_session_propagation","severity":"high",
                                 "memory_id":mid,"read_sessions":other,"fanout":len(other)})
    return {
        "schema":"ai-dfir/memory-lineage/v0.9",
        "memory_objects":len(writes),"lineage":lineage,
        "cross_session":cross_session,"findings":findings,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--events",required=True);ap.add_argument("--trusted-writer",action="append",default=[])
    ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load_events(a.events),a.trusted_writer)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
