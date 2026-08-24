#!/usr/bin/env python3
"""Agent session ownership, async task hijacking, and outstanding delegated-work analysis."""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path

TERMINAL={"completed","failed","cancelled","canceled","expired","terminated"}

def load(path):
    rows=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:rows.append(json.loads(line))
            except Exception:pass
    return rows

def analyze(rows):
    owners={};tasks={};findings=[];containment_time={}
    for e in rows:
        et=e.get("event_type") or e.get("type")
        sid=e.get("session_id")
        if et in ("session_created","session_owner"):
            owner=e.get("owner") or e.get("principal")
            if sid in owners and owners[sid]!=owner:
                findings.append({"type":"session_owner_changed","severity":"critical",
                                 "session_id":sid,"old_owner":owners[sid],"new_owner":owner,"event":e})
            owners[sid]=owner
        if et=="session_access" and sid and owners.get(sid) and e.get("principal")!=owners[sid]:
            if not (e.get("metadata") or {}).get("delegated",False):
                findings.append({"type":"session_access_by_non_owner","severity":"critical","session_id":sid,"event":e})
        tid=e.get("task_id")
        if tid:
            t=tasks.setdefault(tid,{"task_id":tid,"origin_agent":e.get("agent_id") or e.get("actor_id"),
                                    "origin_event_id":e.get("origin_event_id") or e.get("parent_event_id"),
                                    "authority_id":e.get("authority_id"),"state":None,"last_event":None,
                                    "executor":e.get("executor"),"cancelable":None})
            t["last_event"]=e;t["state"]=e.get("state") or e.get("status") or t["state"]
            if "cancelable" in e:t["cancelable"]=e["cancelable"]
            if e.get("executor"):t["executor"]=e["executor"]
        aid=e.get("agent_id") or e.get("actor_id")
        if et in ("containment","agent_stop","agent_terminated") and aid:
            containment_time[aid]=e.get("timestamp_utc")
    outstanding=[]
    for t in tasks.values():
        state=str(t.get("state") or "unknown").lower()
        if state not in TERMINAL:
            outstanding.append(t)
            if t["origin_agent"] in containment_time:
                findings.append({"type":"delegated_work_still_active_after_agent_containment",
                                 "severity":"critical","task":t,
                                 "containment_timestamp":containment_time[t["origin_agent"]]})
    return {"schema":"ai-dfir/session-task-analysis/v1.1","session_owners":owners,
            "outstanding_work":outstanding,"outstanding_count":len(outstanding),"findings":findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--log",required=True);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load(a.log));txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
