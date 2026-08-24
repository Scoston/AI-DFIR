#!/usr/bin/env python3
"""
AI-DFIR v0.9 deterministic agentic detection-rule engine.

Rules operate on normalized signal names from forensic analyzers and normalized
event types. No arbitrary expressions/eval are supported.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
DEFAULT_RULES=HERE/"agentic_detection_rules.json"

def load_json(path):
    try:return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:return None

def collect_signals(paths):
    signals=[];event_types=[];details=[]
    for p in paths:
        path=Path(p)
        if not path.exists():continue
        if path.suffix==".jsonl":
            for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
                if not line.strip():continue
                try:o=json.loads(line)
                except Exception:continue
                et=o.get("event_type")
                if et:event_types.append(et)
                if o.get("type"):signals.append(o["type"])
        else:
            o=load_json(path)
            if isinstance(o,list):items=o
            elif isinstance(o,dict):
                items=[]
                for key in ("findings","evidence","alerts"):
                    if isinstance(o.get(key),list):items.extend(o[key])
                if o.get("type"):items.append(o)
            else:items=[]
            for x in items:
                if isinstance(x,dict):
                    if x.get("type"):signals.append(x["type"])
                    if x.get("code"):signals.append(x["code"])
                    details.append(x)
    return set(signals),set(event_types),details

def evaluate(rules,signals,event_types):
    hits=[]
    for r in rules.get("rules",[]):
        req=set(r.get("requires_signals") or [])
        any_sig=set(r.get("any_signals") or [])
        req_ev=set(r.get("requires_event_types") or [])
        any_ev=set(r.get("any_event_types") or [])
        ok=(req.issubset(signals)
            and (not any_sig or bool(any_sig & signals))
            and req_ev.issubset(event_types)
            and (not any_ev or bool(any_ev & event_types)))
        if ok:
            hits.append({
                "rule_id":r["id"],"title":r["title"],"severity":r.get("severity","medium"),
                "owasp_agentic":r.get("owasp_agentic"),"mitre_atlas":r.get("mitre_atlas",[]),
                "matched_signals":sorted((req|any_sig)&signals),
                "matched_event_types":sorted((req_ev|any_ev)&event_types),
                "evidence_pack_id":r.get("evidence_pack_id"),
                "statement":r.get("statement"),
            })
    return hits

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",action="append",required=True)
    ap.add_argument("--rules",default=str(DEFAULT_RULES))
    ap.add_argument("--out")
    a=ap.parse_args()
    rules=load_json(a.rules);signals,events,_=collect_signals(a.input)
    result={"schema":"ai-dfir/agentic-rule-findings/v0.9",
            "signals":sorted(signals),"event_types":sorted(events),
            "findings":evaluate(rules,signals,events)}
    txt=json.dumps(result,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
