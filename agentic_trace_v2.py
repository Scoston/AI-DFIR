#!/usr/bin/env python3
"""
AI-DFIR v0.9 normalized agentic event schema and validator.

This does not require a particular agent framework. Events can be produced by
MCP gateways, orchestrators, custom agents, cloud audit logs, RAG middleware,
memory services, and AI provider telemetry.

Causality is explicit:
- parent_event_id: direct parent in execution flow
- cause_event_ids: one or more evidentiary causes
- correlation_ids: association only; NOT causation
"""
from __future__ import annotations
import argparse, hashlib, json, uuid
from datetime import datetime, timezone
from pathlib import Path

EVENT_TYPES = {
    "human_input","model_input","model_output","retrieval_query","retrieval_result",
    "memory_read","memory_write","memory_update","memory_delete",
    "tool_discovery","tool_call","tool_result","mcp_request","mcp_response",
    "delegation","agent_message","approval_request","approval_decision",
    "identity_issue","identity_use","policy_decision","code_execution",
    "network_action","data_access","data_write","consequence","containment",
    "harness_event","prompt_assembly","middleware_event","stop_requested","cancel_requested",
    "session_created","session_owner","session_access","session_transfer",
    "task_created","task_update","task_cancel","task_complete",
    "browser_navigation","browser_action","browser_network","browser_render",
    "a2a_message","a2a_task","a2a_agent_card",
    "cache_read","cache_write","cache_invalidate","router_resolution",
    "workspace_instruction","render_output"
}

def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def sha256_text(s):
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

def make_event(event_type, actor_id, *, event_id=None, timestamp_utc=None,
               target_id=None, parent_event_id=None, cause_event_ids=None,
               correlation_ids=None, content=None, content_sha256=None,
               authority_id=None, session_id=None, trace_id=None, metadata=None):
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unsupported event_type={event_type}")
    return {
        "schema":"ai-dfir/agentic-event/v1.1",
        "event_id":event_id or str(uuid.uuid4()),
        "timestamp_utc":timestamp_utc or utc_now(),
        "event_type":event_type,
        "actor_id":actor_id,
        "target_id":target_id,
        "parent_event_id":parent_event_id,
        "cause_event_ids":sorted(set(cause_event_ids or [])),
        "correlation_ids":sorted(set(correlation_ids or [])),
        "content_sha256":content_sha256 or (sha256_text(content) if content is not None else None),
        "authority_id":authority_id,
        "session_id":session_id,
        "trace_id":trace_id,
        "metadata":metadata or {},
    }

def validate_event(e):
    errors=[]
    if e.get("schema") not in ("ai-dfir/agentic-event/v0.9","ai-dfir/agentic-event/v1.1"):errors.append("schema")
    if e.get("event_type") not in EVENT_TYPES:errors.append("event_type")
    if not e.get("event_id"):errors.append("event_id")
    if not e.get("timestamp_utc"):errors.append("timestamp_utc")
    if not e.get("actor_id"):errors.append("actor_id")
    if e.get("event_id") in (e.get("cause_event_ids") or []):errors.append("self_cause")
    return errors

def validate_file(path: Path):
    seen=set();rows=[];errors=[]
    for i,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
        if not line.strip():continue
        try:e=json.loads(line)
        except Exception as ex:
            errors.append({"line":i,"error":f"json:{ex}"});continue
        es=validate_event(e)
        if e.get("event_id") in seen:es.append("duplicate_event_id")
        seen.add(e.get("event_id"))
        if es:errors.append({"line":i,"event_id":e.get("event_id"),"errors":es})
        rows.append(e)
    # References may point outside a partial export, so missing references are warnings.
    ids={e.get("event_id") for e in rows}
    warnings=[]
    for e in rows:
        refs=([e.get("parent_event_id")] if e.get("parent_event_id") else [])+(e.get("cause_event_ids") or [])
        missing=[x for x in refs if x not in ids]
        if missing:warnings.append({"event_id":e.get("event_id"),"missing_references":missing})
    return {"valid":not errors,"events":len(rows),"errors":errors,"warnings":warnings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("validate");p.add_argument("--file",required=True)
    p=sp.add_parser("event")
    p.add_argument("--type",required=True,choices=sorted(EVENT_TYPES));p.add_argument("--actor",required=True)
    p.add_argument("--target");p.add_argument("--parent");p.add_argument("--cause",action="append",default=[])
    p.add_argument("--correlation",action="append",default=[]);p.add_argument("--content")
    p.add_argument("--authority");p.add_argument("--session");p.add_argument("--trace")
    p.add_argument("--metadata-json")
    args=ap.parse_args()
    if args.cmd=="validate":
        x=validate_file(Path(args.file));print(json.dumps(x,indent=2,sort_keys=True));raise SystemExit(0 if x["valid"] else 1)
    meta=json.loads(args.metadata_json) if args.metadata_json else {}
    print(json.dumps(make_event(args.type,args.actor,target_id=args.target,parent_event_id=args.parent,
          cause_event_ids=args.cause,correlation_ids=args.correlation,content=args.content,
          authority_id=args.authority,session_id=args.session,trace_id=args.trace,metadata=meta),
          indent=2,sort_keys=True))
if __name__=="__main__":main()
