#!/usr/bin/env python3
"""RAG corpus diff, retrieval provenance, and poisoning blast-radius analysis."""
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict
from pathlib import Path

def load_jsonl(p):
    out=[]
    for line in Path(p).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def corpus_map(obj):
    docs=obj.get("documents",obj if isinstance(obj,list) else [])
    return {d.get("document_id") or d.get("uri") or d.get("path"):d for d in docs}

def corpus_diff(a,b):
    aa,bb=corpus_map(a),corpus_map(b);findings=[]
    for k in sorted(set(bb)-set(aa)):
        findings.append({"type":"rag_document_added","severity":"high","document":k,
                         "sha256":bb[k].get("sha256"),"source":bb[k].get("source")})
    for k in sorted(set(aa)-set(bb)):
        findings.append({"type":"rag_document_removed","severity":"medium","document":k})
    for k in sorted(set(aa)&set(bb)):
        for field in ("sha256","acl_sha256","metadata_sha256"):
            if aa[k].get(field)!=bb[k].get(field):
                findings.append({"type":f"rag_{field}_changed","severity":"critical" if field=="sha256" else "high",
                                 "document":k,"approved":aa[k].get(field),"suspect":bb[k].get(field)})
    return findings

def provenance(events, poisoned_hashes=None):
    poisoned=set(poisoned_hashes or [])
    sessions=defaultdict(lambda:{"retrieved":[],"included":[],"downstream_tools":[],"consequences":[]})
    graph={"nodes":{},"edges":[]}
    def node(i,kind,label,meta=None):
        if i:graph["nodes"].setdefault(i,{"id":i,"kind":kind,"label":label,**(meta or {})})
    for e in events:
        sid=e.get("session_id") or e.get("trace_id") or "unknown"
        et=e.get("event_type")
        eid=e.get("event_id")
        if et=="retrieval_result":
            h=e.get("content_sha256") or (e.get("metadata") or {}).get("chunk_sha256")
            doc=(e.get("metadata") or {}).get("document_id") or e.get("target_id")
            sessions[sid]["retrieved"].append({"event_id":eid,"hash":h,"document":doc})
            if (e.get("metadata") or {}).get("included_in_prompt"):
                sessions[sid]["included"].append({"event_id":eid,"hash":h,"document":doc})
        elif et=="tool_call":
            sessions[sid]["downstream_tools"].append(eid)
        elif et=="consequence":
            sessions[sid]["consequences"].append(eid)
        node(eid,et,e.get("target_id") or et,{"session_id":sid})
        if e.get("parent_event_id"):graph["edges"].append({"source":e["parent_event_id"],"target":eid,"relation":"parent","causal":True})
        for c in e.get("cause_event_ids") or []:graph["edges"].append({"source":c,"target":eid,"relation":"cause","causal":True})
        for c in e.get("correlation_ids") or []:graph["edges"].append({"source":c,"target":eid,"relation":"correlation","causal":False})
    affected=[]
    for sid,x in sessions.items():
        bad=[r for r in x["included"] if r["hash"] in poisoned]
        if bad:
            affected.append({"session_id":sid,"poisoned_context":bad,
                             "downstream_tool_calls":x["downstream_tools"],
                             "consequences":x["consequences"]})
    return {"schema":"ai-dfir/rag-provenance/v0.9","affected_sessions":affected,
            "affected_session_count":len(affected),"graph":{"nodes":list(graph["nodes"].values()),"edges":graph["edges"]}}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    p=sp.add_parser("trace");p.add_argument("--events",required=True);p.add_argument("--poisoned-hash",action="append",default=[]);p.add_argument("--out")
    a=ap.parse_args()
    if a.cmd=="diff":obj=corpus_diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text()))
    else:obj=provenance(load_jsonl(a.events),a.poisoned_hash)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
