#!/usr/bin/env python3
"""
Merge AI-DFIR evidence into a normalized forensic timeline.

Supports:
- v0.3/v0.4 attestation JSONL
- agent_trace JSONL
- optional bpftrace collector directory
- arbitrary JSONL containing timestamp_utc

eBPF UTC timestamps are estimated relative to collector start and the first
monotonic bpftrace event; the timeline marks them as estimated.
"""
import argparse, csv, json
from datetime import datetime, timezone, timedelta
from pathlib import Path


SUSPICIOUS_TERMS = (
    "adapter", "lora", "peft", "forward_hook", "control", "direction",
    "steering", "abliter", "uncensored", "safetensors"
)


def dt(s):
    return datetime.fromisoformat(s.replace("Z","+00:00"))


def parse_jsonl(label,path):
    out=[]
    with open(path,encoding="utf-8") as f:
        for i,line in enumerate(f,1):
            if not line.strip():continue
            try:e=json.loads(line)
            except:continue
            ts=e.get("timestamp_utc") or e.get("time_utc")
            if not ts:continue
            meta=e.get("metadata") or {}
            offset_ms=e.get("clock_offset_ms_to_utc",meta.get("clock_offset_ms_to_utc",0)) or 0
            uncertainty_ms=e.get("clock_uncertainty_ms",meta.get("clock_uncertainty_ms",0)) or 0
            observed=dt(ts)
            adjusted=observed+timedelta(milliseconds=float(offset_ms))
            out.append({
                "timestamp_utc":adjusted.isoformat().replace("+00:00","Z"),
                "source_timestamp":ts,
                "source":label,
                "event_type":e.get("event_type") or e.get("kind") or "event",
                "summary":e.get("name") or e.get("prompt_id") or e.get("status") or "",
                "details":e,
                "timestamp_quality":"observed" if not uncertainty_ms else "observed_with_uncertainty",
                "clock_offset_ms_to_utc":float(offset_ms),
                "clock_uncertainty_ms":float(uncertainty_ms),
                "interval_start_utc":(adjusted-timedelta(milliseconds=float(uncertainty_ms))).isoformat().replace("+00:00","Z"),
                "interval_end_utc":(adjusted+timedelta(milliseconds=float(uncertainty_ms))).isoformat().replace("+00:00","Z"),
            })
    return out


def parse_ebpf(directory):
    directory=Path(directory)
    events_file=directory/"events.jsonl"
    start_file=directory/"start_utc.txt"
    if not events_file.exists() or not start_file.exists():return []
    start=dt(start_file.read_text().strip())
    raw=[]
    for line in events_file.read_text(encoding="utf-8",errors="ignore").splitlines():
        try:e=json.loads(line)
        except:continue
        if "ts_ns" in e:raw.append(e)
    if not raw:return []
    first=min(int(e["ts_ns"]) for e in raw)
    out=[]
    for e in raw:
        estimate=start+timedelta(seconds=(int(e["ts_ns"])-first)/1e9)
        path=e.get("path","")
        flags=[t for t in SUSPICIOUS_TERMS if t in path.lower()]
        out.append({
            "timestamp_utc":estimate.isoformat().replace("+00:00","Z"),
            "source":"ebpf",
            "event_type":e.get("kind","syscall"),
            "summary":path or e.get("comm",""),
            "details":e,
            "timestamp_quality":"estimated_from_collector_start",
            "clock_offset_ms_to_utc":0.0,
            "clock_uncertainty_ms":1000.0,
            "interval_start_utc":(estimate-timedelta(seconds=1)).isoformat().replace("+00:00","Z"),
            "interval_end_utc":(estimate+timedelta(seconds=1)).isoformat().replace("+00:00","Z"),
            "suspicious_terms":flags,
        })
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",action="append",default=[],help="LABEL=JSONL")
    ap.add_argument("--ebpf-dir",default=None)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    events=[]
    for spec in args.source:
        label,path=spec.split("=",1)
        events.extend(parse_jsonl(label,path))
    if args.ebpf_dir:events.extend(parse_ebpf(args.ebpf_dir))
    events.sort(key=lambda e:dt(e["timestamp_utc"]))
    previous=None
    for e in events:
        e["ordering_ambiguous_with_previous"]=False
        if previous:
            prev_end=dt(previous.get("interval_end_utc") or previous["timestamp_utc"])
            cur_start=dt(e.get("interval_start_utc") or e["timestamp_utc"])
            if cur_start <= prev_end:
                e["ordering_ambiguous_with_previous"]=True
                previous["ordering_ambiguous_with_next"]=True
        previous=e

    # Identify first notable runtime file/open event as a correlation candidate.
    correlated=None
    for e in events:
        text=(e.get("summary") or "").lower()
        if any(t in text for t in SUSPICIOUS_TERMS):
            correlated={
                "timestamp_utc":e["timestamp_utc"],
                "source":e["source"],
                "event_type":e["event_type"],
                "summary":e["summary"],
            }
            break

    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    result={
        "schema":"ai-dfir/timeline/v1.1",
        "event_count":len(events),
        "correlated_change_event":correlated,
        "events":events,
    }
    (out/"timeline.json").write_text(json.dumps(result,indent=2,sort_keys=True,default=str))

    with (out/"timeline.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);w.writerow(["timestamp_utc","quality","uncertainty_ms","ordering_ambiguous","source","event_type","summary"])
        for e in events:w.writerow([e["timestamp_utc"],e["timestamp_quality"],e.get("clock_uncertainty_ms",0),e.get("ordering_ambiguous_with_previous",False),e["source"],e["event_type"],e["summary"]])

    md=["# AI-DFIR Forensic Timeline","",f"- Events: **{len(events)}**",
        f"- First correlated change candidate: **{correlated}**","","| Time (UTC) | Source | Event | Summary |",
        "|---|---|---|---|"]
    for e in events[:200]:
        summary=str(e["summary"]).replace("|","\\|")[:160]
        md.append(f"| {e['timestamp_utc']} | {e['source']} | {e['event_type']} | {summary} |")
    (out/"timeline.md").write_text("\n".join(md)+"\n")
    print(json.dumps({"events":len(events),"correlated_change_event":correlated},indent=2))

if __name__=="__main__":main()
