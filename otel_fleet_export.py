#!/usr/bin/env python3
"""
Export collector fleet state as OpenTelemetry-style security telemetry JSONL.

This does not claim the custom ai_dfir.* attributes are standardized GenAI
semantic-convention fields. Stable/common resource names and selected GenAI
model attributes are kept separate from AI-DFIR extension attributes.
"""
import argparse, json, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path


def get(url):
    with urllib.request.urlopen(url,timeout=10) as r:return json.loads(r.read())


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--collector",default="http://127.0.0.1:8787")
    ap.add_argument("--out",required=True)
    ap.add_argument("--service-name",default="ai-dfir-fleet-attestation")
    args=ap.parse_args()
    fleet=get(args.collector.rstrip("/")+"/v1/fleet")
    now=time.time_ns()
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("a",encoding="utf-8") as f:
        for n in fleet.get("nodes",[]):
            rec={
                "resource":{
                    "service.name":args.service_name,
                    "service.instance.id":n["node_id"],
                },
                "metric":{
                    "name":"ai_dfir.fleet.node.state",
                    "time_unix_nano":now,
                    "value":1,
                    "attributes":{
                        "ai_dfir.node.id":n["node_id"],
                        "ai_dfir.state":n["state"],
                        "ai_dfir.stale":bool(n.get("stale")),
                        "ai_dfir.last_seq":n.get("last_seq"),
                        "ai_dfir.heartbeat.age_seconds":n.get("age_seconds"),
                    }
                }
            }
            f.write(json.dumps(rec,sort_keys=True)+"\n")
    print(f"Wrote {len(fleet.get('nodes',[]))} OpenTelemetry-style metric records to {out}")


if __name__=="__main__":main()
