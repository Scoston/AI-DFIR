#!/usr/bin/env python3
"""
Ingest an OPTIONAL isolated semantic-classifier verdict.

This module does not call a model. It validates that a classifier result is
bound to the exact quarantined source SHA-256 and contains only bounded,
non-executable verdict metadata.

This keeps semantic classification outside the privileged investigation agent.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

ALLOWED_VERDICTS={"benign","suspicious","malicious","unknown"}
ALLOWED_KEYS={"schema","source_sha256","verdict","confidence","categories","classifier",
              "classifier_version","analysis_id","notes","timestamp_utc"}
MAX_NOTES=4000
DANGEROUS_KEYS={"tool_calls","commands","code","raw_source","prompt","system_prompt","instructions","actions"}

def sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()

def validate(source_path,result):
    findings=[]
    source_digest=sha(source_path)
    extra=set(result)-ALLOWED_KEYS
    dangerous=extra&DANGEROUS_KEYS
    if dangerous:
        findings.append({"type":"semantic_verdict_contains_executable_fields","severity":"critical",
                         "fields":sorted(dangerous)})
    if extra-dangerous:
        findings.append({"type":"semantic_verdict_unrecognized_fields","severity":"medium",
                         "fields":sorted(extra-dangerous)})
    if result.get("source_sha256")!=source_digest:
        findings.append({"type":"semantic_verdict_source_hash_mismatch","severity":"critical",
                         "expected":source_digest,"actual":result.get("source_sha256")})
    verdict=str(result.get("verdict","unknown")).lower()
    if verdict not in ALLOWED_VERDICTS:
        findings.append({"type":"semantic_verdict_invalid_value","severity":"high","verdict":verdict})
    conf=result.get("confidence")
    if conf is not None:
        try:
            conf=float(conf)
            if not 0<=conf<=1:raise ValueError
        except Exception:
            findings.append({"type":"semantic_verdict_invalid_confidence","severity":"high","confidence":conf})
    notes=str(result.get("notes") or "")
    if len(notes)>MAX_NOTES:
        findings.append({"type":"semantic_verdict_notes_too_long","severity":"medium","length":len(notes)})
    sanitized={
      "schema":"ai-dfir/semantic-verdict/v1.2","source_sha256":source_digest,
      "verdict":verdict if verdict in ALLOWED_VERDICTS else "unknown",
      "confidence":conf if isinstance(conf,float) else result.get("confidence"),
      "categories":[str(x)[:200] for x in (result.get("categories") or [])[:50]],
      "classifier":str(result.get("classifier") or "")[:200],
      "classifier_version":str(result.get("classifier_version") or "")[:200],
      "analysis_id":str(result.get("analysis_id") or "")[:200],
      "timestamp_utc":result.get("timestamp_utc"),
      "valid":not any(x["severity"] in ("critical","high") for x in findings),
      "findings":findings,
      "rule":"Semantic verdict is corroborative only and never authorizes tool execution or overrides deterministic quarantine."
    }
    return sanitized

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source",required=True);ap.add_argument("--result",required=True);ap.add_argument("--out")
    a=ap.parse_args();obj=validate(a.source,json.loads(Path(a.result).read_text()))
    text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
    if not obj["valid"]:raise SystemExit(2)
if __name__=="__main__":main()
