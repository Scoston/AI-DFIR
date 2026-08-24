#!/usr/bin/env python3
"""
Source-to-sink AI taint propagation for normalized agentic events.

This is forensic provenance, not a runtime sanitizer. It propagates labels only
over explicit parent/cause relationships. Correlation IDs are recorded but do
not propagate taint unless the operator opts in.
"""
from __future__ import annotations
import argparse, hashlib, json, uuid
from collections import defaultdict, deque
from pathlib import Path

SINK_TYPES={"tool_call","code_execution","network_action","data_write","consequence","memory_write","delegation","agent_message"}

def load_events(p):
    out=[]
    for line in Path(p).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def analyze(events,seed_ids=None,seed_hashes=None):
    nodes={e.get("event_id"):e for e in events if e.get("event_id")}
    children=defaultdict(list)
    correlations=defaultdict(list)
    for e in events:
        eid=e.get("event_id")
        if e.get("parent_event_id"):children[e["parent_event_id"]].append(eid)
        for c in e.get("cause_event_ids") or []:children[c].append(eid)
        for c in e.get("correlation_ids") or []:correlations[c].append(eid)

    seeds=set(seed_ids or [])
    sh=set(seed_hashes or [])
    for e in events:
        meta=e.get("metadata") or {}
        if meta.get("untrusted") or meta.get("taint_seed") or (e.get("content_sha256") in sh):
            seeds.add(e["event_id"])

    labels={}
    for sid in seeds:
        e=nodes.get(sid)
        if not e:continue
        labels[sid]={
            "taint_id":meta_taint_id(e),
            "source_event_id":sid,
            "source_content_sha256":e.get("content_sha256"),
            "source_actor":e.get("actor_id"),
            "source_type":e.get("event_type"),
            "trust_level":(e.get("metadata") or {}).get("trust_level","untrusted"),
        }

    taints=defaultdict(dict)
    q=deque()
    for sid,label in labels.items():
        taints[sid][label["taint_id"]]=label;q.append(sid)
    while q:
        cur=q.popleft()
        for nxt in children.get(cur,[]):
            before=len(taints[nxt])
            for tid,label in taints[cur].items():taints[nxt].setdefault(tid,label)
            if len(taints[nxt])>before:q.append(nxt)

    lineage=[];sinks=[];propagation_sessions=defaultdict(set)
    for eid,tm in taints.items():
        e=nodes[eid]
        item={"event_id":eid,"event_type":e.get("event_type"),"actor_id":e.get("actor_id"),
              "target_id":e.get("target_id"),"session_id":e.get("session_id"),
              "trace_id":e.get("trace_id"),"taints":sorted(tm)}
        lineage.append(item)
        for tid in tm: propagation_sessions[tid].add(e.get("session_id"))
        if e.get("event_type") in SINK_TYPES:
            sinks.append(item)

    spread=[]
    for tid,sessions in propagation_sessions.items():
        clean=sorted(x for x in sessions if x)
        if len(clean)>1:spread.append({"taint_id":tid,"sessions":clean,"session_count":len(clean)})

    return {"schema":"ai-dfir/taint-analysis/v1.1","seed_event_ids":sorted(seeds),
            "lineage":lineage,"sinks":sinks,"cross_session_spread":spread,
            "correlation_edges_not_propagated":sum(len(v) for v in correlations.values()),
            "rule":"Taint propagates only over explicit parent/cause edges; correlation alone is not causal proof."}

def meta_taint_id(e):
    m=e.get("metadata") or {}
    return m.get("taint_id") or "TAINT-"+hashlib.sha256(
        (str(e.get("event_id"))+"|"+str(e.get("content_sha256"))).encode()).hexdigest()[:16]

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--events",required=True)
    ap.add_argument("--seed",action="append",default=[]);ap.add_argument("--seed-hash",action="append",default=[])
    ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load_events(a.events),a.seed,a.seed_hash)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
