#!/usr/bin/env python3
"""
Deterministic adversarial-content intake gate.

The gate is intentionally non-agentic: it performs static parsing and never
sends untrusted content to an LLM, executes document macros, loads external
resources, or renders terminal control sequences.

Verdicts:
  PASS        no high/critical representation finding
  REVIEW      high finding
  QUARANTINE  critical finding
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import v17_html_intake as html_intake
import v17_content_intake as bounded_content
from v17_integrity import sha256_bytes
from evil_font_forensics import analyze_docx,analyze_pdf,analyze_html
from archive_intake_forensics import analyze as archive_analyze

def findings(o):return o.get("findings",[]) if isinstance(o,dict) else []
def scan(path):
    p=Path(path);ext=p.suffix.lower();analyses={};captured=None
    if ext==".docx":
        try:analyses["document_font"]=analyze_docx(p)
        except Exception:analyses["document_font"]={"findings":[{"type":"docx_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable DOCX"}]}
    elif ext==".pdf":
        try:analyses["document_font"]=analyze_pdf(p)
        except Exception:analyses["document_font"]={"findings":[{"type":"pdf_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable PDF"}]}
    elif ext in (".html",".htm"):
        try:
            captured=html_intake.capture(p)
            analyses["document_font"]=analyze_html(p,captured=captured)
        except Exception:analyses["document_font"]={"findings":[{"type":"html_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable HTML/CSS"}]}
    elif ext in (".ttf",".otf",".woff",".woff2"):
        try:analyses["font"]=bounded_content.font_file(p)
        except Exception:analyses["font"]={"findings":[{"type":"font_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable font"}]}
    elif ext in (".zip",".tar",".tgz",".gz",".bz2",".xz",".tbz",".tbz2",".txz",".whl",".jar",".vsix"):
        try:analyses["archive"]=archive_analyze(p)
        except Exception:analyses["archive"]={"findings":[{"type":"archive_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable archive"}]}
    if ext in (".txt",".md",".markdown",".html",".htm",".xml",".json",".jsonl",".csv",".yaml",".yml"):
        try:
            if ext in (".html",".htm"):
                html_intake.require(captured is not None)
                raw,text=captured["raw"],captured["text"]
            else:raw,text=html_intake.read_text_snapshot(p)
            worker=bounded_content.run_worker(raw,mode="markup" if ext in (".md",".markdown",".html",".htm") else "plain")
            analyses["text_intake"]={"source_sha256":sha256_bytes(raw),"source_size_bytes":len(raw),"analysis_available":worker.get("available") is True,"findings":[]}
            if worker.get("available") is True:analyses.update(worker["analyses"])
            else:analyses["text_intake"]["findings"].append({"type":"text_analysis_incomplete","severity":"high"})
        except Exception:analyses["text_intake"]={"findings":[{"type":"text_parse_failure","severity":"high","error":"invalid, unsupported, excessive, or unavailable text"}]}
    if not analyses:
        analyses["intake"]={"findings":[{"type":"unsupported_content_type","severity":"high"}]}
    fs=[]
    for domain,obj in analyses.items():
        for x in findings(obj):fs.append({"domain":domain,**x})
    sev={str(x.get("severity","")).lower() for x in fs}
    verdict="QUARANTINE" if "critical" in sev else ("REVIEW" if "high" in sev else "PASS")
    report={"schema":"ai-dfir/content-intake/v1.2","path":str(p.absolute()),"verdict":verdict,
            "findings":fs,"analyses":analyses,
            "rule":"PASS is not proof of safety; it means no modeled deterministic representation signal was detected."}
    try:bounded_content.require(len(bounded_content.canonical_json_bytes(report))<=bounded_content.GATE_OUTPUT_BYTES)
    except Exception:
        report.update(verdict="QUARANTINE" if verdict=="QUARANTINE" else "REVIEW",analyses={},findings=[{"domain":"intake","type":"intake_output_limit","severity":"high"}])
    return report
def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args()
    try:
        obj=scan(a.path)
        bounded_content.output_report(obj,a.out,limit=bounded_content.GATE_OUTPUT_BYTES)
    except KeyboardInterrupt:raise SystemExit(130)
    except Exception:
        print(json.dumps({"status":"FAIL","error":"invalid, unsupported, excessive content or unavailable output"}))
        raise SystemExit(1)
    raise SystemExit({"PASS":0,"REVIEW":1,"QUARANTINE":2}[obj["verdict"]])
if __name__=="__main__":main()
