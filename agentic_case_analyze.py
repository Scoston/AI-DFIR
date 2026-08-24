#!/usr/bin/env python3
"""Run v0.9 agentic analyzers and attach technique evidence packs to a case."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from mcp_forensics import diff as mcp_diff
from rag_forensics import corpus_diff, provenance as rag_provenance, load_jsonl
from memory_forensics import analyze as memory_analyze
from authority_engine import diff as authority_diff
from agentic_graph import analyze as causal_analyze, load_events
from agentic_rules import collect_signals, evaluate as evaluate_rules, load_json

HERE=Path(__file__).resolve().parent

def read(p):return json.loads(Path(p).read_text(encoding="utf-8"))
def write(obj,p):Path(p).write_text(json.dumps(obj,indent=2,sort_keys=True))

def attach_profile(case,pack_ids):
    p=case/"incident_profile.json"
    obj=read(p) if p.exists() else {"schema":"ai-dfir/incident-profile/v0.9"}
    cur=list(obj.get("additional_evidence_pack_ids") or [])
    for x in pack_ids:
        if x and x!=obj.get("evidence_pack_id") and x not in cur:cur.append(x)
    obj["additional_evidence_pack_ids"]=sorted(cur)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case",required=True)
    ap.add_argument("--events")
    ap.add_argument("--mcp-approved");ap.add_argument("--mcp-suspect")
    ap.add_argument("--rag-approved");ap.add_argument("--rag-suspect")
    ap.add_argument("--poisoned-hash",action="append",default=[])
    ap.add_argument("--trusted-memory-writer",action="append",default=[])
    ap.add_argument("--authority-approved");ap.add_argument("--authority-suspect")
    ap.add_argument("--seed",action="append",default=[])
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True)
    generated=[];rule_inputs=[]

    if a.mcp_approved and a.mcp_suspect:
        obj=mcp_diff(read(a.mcp_approved),read(a.mcp_suspect));p=case/"mcp_findings.json";write(obj,p);generated.append(str(p));rule_inputs.append(str(p))
    if a.rag_approved and a.rag_suspect:
        obj={"schema":"ai-dfir/rag-findings/v0.9","findings":corpus_diff(read(a.rag_approved),read(a.rag_suspect))}
        p=case/"rag_findings.json";write(obj,p);generated.append(str(p));rule_inputs.append(str(p))
    events=load_events(a.events) if a.events else []
    if events:
        mem=memory_analyze(events,a.trusted_memory_writer);p=case/"memory_lineage.json";write(mem,p);generated.append(str(p));rule_inputs.append(str(p))
        causal=causal_analyze(events,a.seed or None)
        # Promote an explicit signal only if there is a causal path reaching a consequence.
        if causal.get("causal_paths") and len(causal.get("affected_agents") or []) >= 2:
            causal["findings"]=[{"type":"causal_cascade_detected","severity":"critical",
                                 "path_count":len(causal["causal_paths"]),
                                 "affected_agents":causal.get("affected_agents")} ]
        p=case/"causal_analysis.json";write(causal,p);generated.append(str(p));rule_inputs.append(str(p));rule_inputs.append(a.events)
        if a.poisoned_hash:
            rag=rag_provenance(events,a.poisoned_hash);p=case/"rag_provenance.json";write(rag,p);generated.append(str(p))
    if a.authority_approved and a.authority_suspect:
        obj=authority_diff(read(a.authority_approved),read(a.authority_suspect));p=case/"authority_diff.json";write(obj,p);generated.append(str(p));rule_inputs.append(str(p))

    rules=load_json(HERE/"agentic_detection_rules.json")
    signals,event_types,_=collect_signals(rule_inputs)
    rf={"schema":"ai-dfir/agentic-rule-findings/v0.9","signals":sorted(signals),
        "event_types":sorted(event_types),"findings":evaluate_rules(rules,signals,event_types)}
    rp=case/"agentic_rule_findings.json";write(rf,rp);generated.append(str(rp))
    attach_profile(case,[x.get("evidence_pack_id") for x in rf["findings"]])
    result={"schema":"ai-dfir/agentic-analysis-run/v0.9","generated":generated,
            "rule_findings":rf["findings"],"secondary_evidence_packs":
            sorted(set(x.get("evidence_pack_id") for x in rf["findings"] if x.get("evidence_pack_id")))}
    write(result,case/"agentic_analysis_run.json")
    print(json.dumps(result,indent=2,sort_keys=True))
if __name__=="__main__":main()
