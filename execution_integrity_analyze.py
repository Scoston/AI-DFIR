#!/usr/bin/env python3
"""Run v1.1 execution-integrity analyzers and attach matching Evidence Packs."""
from __future__ import annotations
import argparse,json,shutil
from pathlib import Path

from harness_forensics import diff as harness_diff, analyze_lifecycle
from browser_forensics import analyze as browser_analyze, load as load_browser
from session_task_forensics import analyze as session_analyze, load as load_session
from a2a_forensics import diff_cards, analyze_events as a2a_analyze, load_jsonl as load_a2a
from router_forensics import analyze as router_analyze, load_jsonl as load_router
from cache_forensics import analyze as cache_analyze, load_records
from prompt_replication import analyze as replication_analyze
from taint_tracker import analyze as taint_analyze, load_events
from agent_lifecycle import analyze as lifecycle_analyze
from evidence_pack_engine import create_profile
from workspace_trust import inventory as workspace_inventory, diff as workspace_diff
from output_render_forensics import analyze as render_analyze, read as read_text, load_jsonl as load_render_network
from tool_identity import analyze as tool_identity_analyze
from mcp_execution_integrity import analyze as mcp_integrity_analyze, load as load_mcp_integrity

HERE=Path(__file__).resolve().parent

def read(p):return json.loads(Path(p).read_text(encoding="utf-8"))
def write(p,o):Path(p).write_text(json.dumps(o,indent=2,sort_keys=True,default=str),encoding="utf-8")

def signals_from(obj):
    out=set()
    if isinstance(obj,list):
        for x in obj:
            if isinstance(x,dict):
                if x.get("type"):out.add(x["type"])
                if x.get("code"):out.add(x["code"])
    elif isinstance(obj,dict):
        if obj.get("type"):out.add(obj["type"])
        for k in ("findings","alerts"):
            out |= signals_from(obj.get(k) or [])
    return out

def attach(case,packs):
    prof=case/"incident_profile.json"
    obj=read(prof) if prof.exists() else {"schema":"ai-dfir/incident-profile/v1.1"}
    cur=list(obj.get("additional_evidence_pack_ids") or [])
    for x in packs:
        if x and x!=obj.get("evidence_pack_id") and x not in cur:cur.append(x)
    obj["schema"]="ai-dfir/incident-profile/v1.1";obj["additional_evidence_pack_ids"]=sorted(cur)
    prof.write_text(json.dumps(obj,indent=2,sort_keys=True))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case",required=True)
    ap.add_argument("--events")
    ap.add_argument("--harness-approved");ap.add_argument("--harness-suspect");ap.add_argument("--harness-log")
    ap.add_argument("--browser-log");ap.add_argument("--approved-browser-origin",action="append",default=[]);ap.add_argument("--approved-websocket-origin",action="append",default=[])
    ap.add_argument("--session-task-log")
    ap.add_argument("--a2a-approved-card");ap.add_argument("--a2a-suspect-card");ap.add_argument("--a2a-log")
    ap.add_argument("--router-policy");ap.add_argument("--router-log")
    ap.add_argument("--cache-records");ap.add_argument("--cache-source-manifest")
    ap.add_argument("--replication-records");ap.add_argument("--replication-threshold",type=float,default=.82)
    ap.add_argument("--taint-seed",action="append",default=[]);ap.add_argument("--taint-seed-hash",action="append",default=[])
    ap.add_argument("--workspace-approved-root");ap.add_argument("--workspace-suspect-root")
    ap.add_argument("--render-raw");ap.add_argument("--render-sanitized");ap.add_argument("--rendered-dom");ap.add_argument("--render-network-log")
    ap.add_argument("--approved-render-origin",action="append",default=[])
    ap.add_argument("--tool-identity-inventory");ap.add_argument("--tool-executions")
    ap.add_argument("--mcp-integrity-log");ap.add_argument("--mcp-root",action="append",default=[])
    a=ap.parse_args();case=Path(a.case);case.mkdir(parents=True,exist_ok=True)
    generated=[];all_signals=set()

    def emit(name,obj):
        p=case/name;write(p,obj);generated.append(str(p));all_signals.update(signals_from(obj));return obj

    if a.harness_approved and a.harness_suspect:
        emit("harness_findings.json",harness_diff(read(a.harness_approved),read(a.harness_suspect)))
    if a.harness_log:
        emit("harness_lifecycle_analysis.json",analyze_lifecycle(a.harness_log))
    if a.browser_log:
        emit("browser_analysis.json",browser_analyze(load_browser(a.browser_log),a.approved_browser_origin,a.approved_websocket_origin))
    if a.session_task_log:
        emit("session_task_analysis.json",session_analyze(load_session(a.session_task_log)))
    if a.a2a_approved_card and a.a2a_suspect_card:
        emit("a2a_card_findings.json",diff_cards(read(a.a2a_approved_card),read(a.a2a_suspect_card)))
    if a.a2a_log:
        emit("a2a_event_analysis.json",a2a_analyze(load_a2a(a.a2a_log)))
    if a.router_policy and a.router_log:
        emit("router_analysis.json",router_analyze(read(a.router_policy),load_router(a.router_log)))
    if a.cache_records:
        src=read(a.cache_source_manifest) if a.cache_source_manifest else {}
        emit("cache_analysis.json",cache_analyze(load_records(a.cache_records),src))
    if a.replication_records:
        obj=read(a.replication_records);emit("prompt_replication_analysis.json",replication_analyze(obj.get("records",obj),a.replication_threshold))
    if a.events:
        events=load_events(a.events)
        emit("taint_analysis.json",taint_analyze(events,a.taint_seed,a.taint_seed_hash))
    if a.workspace_approved_root and a.workspace_suspect_root:
        emit("workspace_trust_diff.json",
             workspace_diff(workspace_inventory(a.workspace_approved_root),workspace_inventory(a.workspace_suspect_root)))
    if a.render_raw:
        emit("output_render_analysis.json",
             render_analyze(read_text(a.render_raw),read_text(a.render_sanitized),read_text(a.rendered_dom),
                            load_render_network(a.render_network_log),a.approved_render_origin))
    if a.tool_identity_inventory:
        inv=read(a.tool_identity_inventory)
        exe=read(a.tool_executions) if a.tool_executions else []
        if isinstance(exe,dict):exe=exe.get("executions",[])
        emit("tool_identity_analysis.json",tool_identity_analyze(inv,exe))
    if a.mcp_integrity_log:
        emit("mcp_execution_integrity.json",mcp_integrity_analyze(load_mcp_integrity(a.mcp_integrity_log),a.mcp_root))

    rules=read(HERE/"execution_integrity_rules.json")
    attached=set()
    matches=[]
    for r in rules["rules"]:
        hit=sorted(set(r["signals"]) & all_signals)
        if hit:
            attached.add(r["pack"])
            matches.append({"pack_id":r["pack"],"severity":r["severity"],"matched_signals":hit})
    attach(case,attached)
    result={"schema":"ai-dfir/execution-integrity-run/v1.1","generated":generated,
            "signals":sorted(all_signals),"evidence_pack_matches":matches,
            "attached_packs":sorted(attached)}
    write(case/"execution_integrity_run.json",result)
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":main()
