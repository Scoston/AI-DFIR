#!/usr/bin/env python3
"""
Multi-agent causal and blast-radius reconstruction.

Only parent_event_id and cause_event_ids create causal edges.
correlation_ids create non-causal correlation edges.

A consequence is attributed to a seed only when a directed causal path exists.
"""
from __future__ import annotations
import argparse, json
from collections import defaultdict, deque
from pathlib import Path

def load_events(p):
    out=[]
    for line in Path(p).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def build(events):
    nodes={e["event_id"]:e for e in events if e.get("event_id")}
    causal=defaultdict(list);corr=defaultdict(list);edges=[]
    for e in events:
        eid=e.get("event_id")
        parent=e.get("parent_event_id")
        if parent:
            causal[parent].append(eid);edges.append({"source":parent,"target":eid,"relation":"parent","causal":True})
        for c in e.get("cause_event_ids") or []:
            causal[c].append(eid);edges.append({"source":c,"target":eid,"relation":"cause","causal":True})
        for c in e.get("correlation_ids") or []:
            corr[c].append(eid);edges.append({"source":c,"target":eid,"relation":"correlation","causal":False})
    return nodes,causal,corr,edges

def descendants(seed,causal):
    seen=set();q=deque([seed])
    while q:
        x=q.popleft()
        for y in causal.get(x,[]):
            if y not in seen:
                seen.add(y);q.append(y)
    return seen

def analyze(events,seed_ids=None):
    nodes,causal,corr,edges=build(events)
    seeds=seed_ids or [e["event_id"] for e in events if (e.get("metadata") or {}).get("suspected_root_cause")]
    paths=[]
    affected_agents=set();tools=set();consequences=[]
    for seed in seeds:
        ds=descendants(seed,causal)
        c=[nodes[x] for x in ds if x in nodes and nodes[x].get("event_type")=="consequence"]
        for x in ds:
            e=nodes.get(x,{})
            if e.get("actor_id"):affected_agents.add(e["actor_id"])
            if e.get("event_type")=="tool_call":tools.add(e.get("target_id") or (e.get("metadata") or {}).get("tool_name"))
        for con in c:
            # reconstruct one shortest causal path
            prev={seed:None};q=deque([seed]);found=False
            while q and not found:
                cur=q.popleft()
                for nxt in causal.get(cur,[]):
                    if nxt in prev:continue
                    prev[nxt]=cur
                    if nxt==con["event_id"]:found=True;break
                    q.append(nxt)
            path=[];cur=con["event_id"]
            while cur is not None and cur in prev:
                path.append(cur);cur=prev[cur]
            path.reverse()
            paths.append({"seed_event_id":seed,"consequence_event_id":con["event_id"],
                          "causal_path":path,"causal":bool(path and path[0]==seed)})
            consequences.append(con["event_id"])
    return {
        "schema":"ai-dfir/agentic-causal-analysis/v0.9",
        "seed_event_ids":seeds,
        "causal_paths":paths,
        "affected_agents":sorted(affected_agents),
        "tools_on_causal_descendant_paths":sorted(x for x in tools if x),
        "consequences":sorted(set(consequences)),
        "causal_edge_count":sum(1 for e in edges if e["causal"]),
        "correlation_edge_count":sum(1 for e in edges if not e["causal"]),
        "graph":{"nodes":list(nodes.values()),"edges":edges},
        "rule":"Timestamp proximity and correlation_ids are not treated as causation."
    }

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--events",required=True)
    ap.add_argument("--seed",action="append",default=[]);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load_events(a.events),a.seed or None)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
