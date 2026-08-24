#!/usr/bin/env python3
"""AI-DFIR v1.4 Runtime Trust Fabric orchestrator."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from workload_identity import analyze as workload_analyze,load as workload_load
from credential_lineage import analyze as credential_analyze,load as credential_load
from temporal_authority import analyze as authority_analyze
from memory_integrity_v2 import analyze as memory_analyze
from mcp_forensics_v14 import analyze as mcp_analyze,load as mcp_load
from otel_genai_ingest import normalize as otel_normalize
from causal_graph_v2 import analyze as causal_analyze,load as causal_load
from collector_health import analyze as health_analyze
from skill_supply_chain import inventory as skill_inventory,diff as skill_diff
from behavioral_sandbox import analyze as sandbox_analyze

HERE=Path(__file__).resolve().parent

def read(p):return json.loads(Path(p).read_text())
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
def collect_signals(o):
    out=set()
    if isinstance(o,dict):
        if o.get('type'):out.add(o['type'])
        for v in o.values():out|=collect_signals(v)
    elif isinstance(o,list):
        for v in o:out|=collect_signals(v)
    return out

def attach(case,packs):
    p=case/'incident_profile.json';obj=read(p) if p.exists() else {'schema':'ai-dfir/incident-profile/v1.4'}
    cur=list(obj.get('additional_evidence_pack_ids') or [])
    for x in sorted(packs):
        if x not in cur and x!=obj.get('evidence_pack_id'):cur.append(x)
    obj['schema']='ai-dfir/incident-profile/v1.4';obj['additional_evidence_pack_ids']=sorted(cur);write(p,obj)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True)
    ap.add_argument('--workload-events');ap.add_argument('--approved-trust-domain',action='append',default=[])
    ap.add_argument('--credential-input');ap.add_argument('--approved-issuer',action='append',default=[])
    ap.add_argument('--authority-policy');ap.add_argument('--authority-events')
    ap.add_argument('--memory-events');ap.add_argument('--memory-baseline');ap.add_argument('--trusted-memory-writer',action='append',default=[])
    ap.add_argument('--mcp-log');ap.add_argument('--approved-mcp-app-origin',action='append',default=[]);ap.add_argument('--approved-mcp-extension',action='append',default=[])
    ap.add_argument('--otel-input')
    ap.add_argument('--causal-events');ap.add_argument('--causal-claims')
    ap.add_argument('--collector-expectations');ap.add_argument('--collector-observations');ap.add_argument('--incident-window')
    ap.add_argument('--approved-skill-root');ap.add_argument('--suspect-skill-root')
    ap.add_argument('--sandbox-declared');ap.add_argument('--sandbox-observed')
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True);generated=[];objs=[]
    def emit(name,o):
        p=case/name;write(p,o);generated.append(str(p));objs.append(o);return o
    if a.workload_events:emit('workload_identity_analysis.json',workload_analyze(workload_load(a.workload_events),a.approved_trust_domain,[]))
    if a.credential_input:emit('credential_lineage_analysis.json',credential_analyze(credential_load(a.credential_input),a.approved_issuer))
    if a.authority_policy and a.authority_events:
        ev=read(a.authority_events);emit('temporal_authority_analysis.json',authority_analyze(read(a.authority_policy),ev.get('events',ev)))
    if a.memory_events:
        ev=read(a.memory_events);base=read(a.memory_baseline) if a.memory_baseline else None;base=base.get('payload',base) if isinstance(base,dict) else base
        emit('memory_integrity_analysis.json',memory_analyze(ev.get('events',ev),base,a.trusted_memory_writer))
    if a.mcp_log:emit('mcp_2026_forensics.json',mcp_analyze(mcp_load(a.mcp_log),a.approved_mcp_app_origin,a.approved_mcp_extension))
    if a.otel_input:emit('otel_genai_ingest.json',otel_normalize(read(a.otel_input),False))
    if a.causal_events:
        claims=read(a.causal_claims) if a.causal_claims else [];claims=claims.get('claims',claims) if isinstance(claims,dict) else claims
        emit('typed_causal_graph.json',causal_analyze(causal_load(a.causal_events),claims))
    if a.collector_expectations and a.collector_observations:
        e=read(a.collector_expectations);o=read(a.collector_observations);w=read(a.incident_window) if a.incident_window else None
        emit('collector_health.json',health_analyze(e.get('sources',e),o.get('sources',o),w))
    if a.approved_skill_root and a.suspect_skill_root:emit('skill_supply_chain_diff.json',skill_diff(skill_inventory(a.approved_skill_root),skill_inventory(a.suspect_skill_root)))
    if a.sandbox_declared and a.sandbox_observed:
        o=read(a.sandbox_observed);emit('behavioral_sandbox_analysis.json',sandbox_analyze(read(a.sandbox_declared),o.get('events',o)))
    signals=set()
    for o in objs:signals|=collect_signals(o)
    rules=read(HERE/'runtime_trust_rules.json');packs=set();matches=[]
    for r in rules['rules']:
        hit=sorted(set(r['signals'])&signals)
        if hit:packs.add(r['pack']);matches.append({'pack_id':r['pack'],'matched_signals':hit})
    attach(case,packs)
    result={'schema':'ai-dfir/runtime-trust-run/v1.4','generated':generated,'signals':sorted(signals),'attached_packs':sorted(packs),'evidence_pack_matches':matches}
    write(case/'runtime_trust_run.json',result);print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
