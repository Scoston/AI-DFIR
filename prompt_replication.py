#!/usr/bin/env python3
"""Prompt/self-replicating instruction propagation detector without embeddings."""
from __future__ import annotations
import argparse, hashlib, json, re
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

def normalize(s):
    s=(s or "").lower()
    s=re.sub(r"\s+"," ",s)
    s=re.sub(r"[^\w\s:/._-]","",s)
    return s.strip()

def shingles(s,n=5):
    t=normalize(s).split()
    return {" ".join(t[i:i+n]) for i in range(max(0,len(t)-n+1))}

def similarity(a,b):
    na,nb=normalize(a),normalize(b)
    if not na or not nb:return 0.0
    seq=SequenceMatcher(None,na,nb).ratio()
    sa,sb=shingles(na),shingles(nb)
    jac=len(sa&sb)/len(sa|sb) if sa|sb else 0.0
    return max(seq,jac)

def analyze(records,threshold=0.82):
    findings=[];edges=[]
    # records: id, text, actor_id, session_id, timestamp, direction/source_type.
    for i,a in enumerate(records):
        for b in records[i+1:]:
            if a.get("actor_id")==b.get("actor_id") and a.get("session_id")==b.get("session_id"):
                continue
            sim=similarity(a.get("text",""),b.get("text",""))
            if sim>=threshold:
                edge={"source":a.get("id"),"target":b.get("id"),"similarity":round(sim,4),
                      "source_actor":a.get("actor_id"),"target_actor":b.get("actor_id"),
                      "source_session":a.get("session_id"),"target_session":b.get("session_id")}
                edges.append(edge)
    # A propagation candidate requires at least two cross-boundary hops or explicit output->input.
    out_by=defaultdict(list);in_by=defaultdict(list)
    byid={x.get("id"):x for x in records}
    for e in edges:
        src=byid.get(e["source"],{});dst=byid.get(e["target"],{})
        if src.get("direction")=="output" and dst.get("direction")=="input":
            findings.append({"type":"prompt_replication_candidate","severity":"high","edge":e})
    # chain fanout
    fan=defaultdict(list)
    for e in edges:fan[e["source"]].append(e)
    for src,es in fan.items():
        targets={(e["target_actor"],e["target_session"]) for e in es}
        if len(targets)>=2:
            findings.append({"type":"prompt_replication_fanout","severity":"critical","source":src,
                             "target_boundaries":len(targets),"edges":es})
    return {"schema":"ai-dfir/prompt-replication-analysis/v1.1","threshold":threshold,
            "edges":edges,"findings":findings,
            "rule":"Similarity establishes propagation candidates, not malicious intent. Causal/behavioral evidence is still required for impact attribution."}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--records",required=True);ap.add_argument("--threshold",type=float,default=.82);ap.add_argument("--out")
    a=ap.parse_args();obj=json.loads(Path(a.records).read_text());records=obj.get("records",obj)
    res=analyze(records,a.threshold);txt=json.dumps(res,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
