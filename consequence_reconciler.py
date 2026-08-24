#!/usr/bin/env python3
"""
Identify downstream consequences that remain open after model containment.

The reconciler consumes v0.4/v0.6 agent-trace events:
- consequence events represent effects that escaped the model boundary
- containment events close a consequence when metadata contains
  `closes_event_id` or `closes_content_sha256`

No destructive action is performed. The output is an investigator/remediation queue.
"""
import argparse, json
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--trace",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    events=[]
    with open(args.trace,encoding="utf-8") as f:
        for line in f:
            if line.strip():events.append(json.loads(line))
    consequences=[e for e in events if e.get("event_type")=="consequence"]
    closed_ids=set();closed_hashes=set()
    for e in events:
        if e.get("event_type")!="containment":continue
        meta=e.get("metadata") or {}
        if meta.get("closes_event_id"):closed_ids.add(meta["closes_event_id"])
        if meta.get("closes_content_sha256"):closed_hashes.add(meta["closes_content_sha256"])
    open_items=[]
    for e in consequences:
        if e.get("event_id") in closed_ids:continue
        if e.get("content_sha256") and e.get("content_sha256") in closed_hashes:continue
        open_items.append({
            "event_id":e.get("event_id"),
            "timestamp_utc":e.get("timestamp_utc"),
            "name":e.get("name"),
            "content_sha256":e.get("content_sha256"),
            "authority_id":e.get("authority_id"),
            "parent_id":e.get("parent_id"),
            "metadata":e.get("metadata"),
        })
    result={
        "schema":"ai-dfir/open-consequences/v0.6",
        "total_consequences":len(consequences),
        "open_count":len(open_items),
        "open_consequences":open_items,
    }
    Path(args.out).parent.mkdir(parents=True,exist_ok=True)
    Path(args.out).write_text(json.dumps(result,indent=2,sort_keys=True))
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":main()
