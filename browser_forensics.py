#!/usr/bin/env python3
"""Browser/computer-use forensic reconstruction for AI agents."""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

ACTION_TYPES={"click","keyboard","upload","download","script_eval","navigation","form_submit","browser_tool_call"}

def load(path):
    rows=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:rows.append(json.loads(line))
            except Exception:pass
    return rows

def analyze(rows,approved_origins=None,approved_ws_origins=None):
    approved=set(approved_origins or []);approved_ws=set(approved_ws_origins or [])
    findings=[];sessions=defaultdict(lambda:{"events":0,"actions":0,"approvals":0,"urls":[]})
    approvals=defaultdict(list)
    for e in rows:
        sid=e.get("session_id") or e.get("browser_id") or "unknown"
        et=e.get("event_type") or e.get("type");sessions[sid]["events"]+=1
        if et=="approval":sessions[sid]["approvals"]+=1;approvals[sid].append(e)
        if et in ACTION_TYPES:
            sessions[sid]["actions"]+=1
            if (e.get("metadata") or {}).get("approval_required") and not (e.get("metadata") or {}).get("approval_event_id"):
                findings.append({"type":"browser_action_without_required_approval","severity":"critical","event":e})
        url=e.get("url") or (e.get("metadata") or {}).get("url")
        if url:sessions[sid]["urls"].append(url)
        if et=="script_eval" and not (e.get("metadata") or {}).get("approved",False):
            findings.append({"type":"unapproved_browser_script_eval","severity":"critical","event":e})
        if et=="network_request":
            origin=origin_of(url)
            if approved and origin and origin not in approved:
                findings.append({"type":"browser_unapproved_network_origin","severity":"high","origin":origin,"event":e})
            if (e.get("metadata") or {}).get("source")=="rendered_model_output" and origin:
                findings.append({"type":"rendered_output_external_request","severity":"high","origin":origin,"event":e})
        if et=="websocket_connect":
            origin=origin_of(url)
            if approved_ws and origin and origin not in approved_ws:
                findings.append({"type":"browser_unapproved_websocket_origin","severity":"critical","origin":origin,"event":e})
        if et=="dom_snapshot" and (e.get("metadata") or {}).get("hidden_instruction_detected"):
            findings.append({"type":"hidden_dom_instruction","severity":"high","event":e})
        if et=="workspace_file_access" and (e.get("metadata") or {}).get("outside_workspace_root"):
            findings.append({"type":"browser_workspace_root_escape","severity":"critical","event":e})
    return {"schema":"ai-dfir/browser-computer-use-analysis/v1.1",
            "sessions":dict(sessions),"findings":findings,
            "recommended_artifacts":["browser profile metadata","process tree","extension inventory",
             "DevTools/CDP events","WebSocket connections","navigation/redirect chain","DOM snapshot",
             "accessibility tree","screenshots","mouse/keyboard events","uploads/downloads","script evaluations",
             "network HAR/proxy/DNS","approval events"]}

def origin_of(url):
    if not url:return None
    try:
        u=urlparse(url);return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else None
    except Exception:return None

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--log",required=True);ap.add_argument("--approved-origin",action="append",default=[])
    ap.add_argument("--approved-websocket-origin",action="append",default=[]);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load(a.log),a.approved_origin,a.approved_websocket_origin)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
