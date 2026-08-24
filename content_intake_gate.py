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
from evil_font_forensics import analyze_docx,analyze_pdf,analyze_html
from unicode_forensics import analyze as unicode_analyze
from markup_representation_forensics import analyze as markup_analyze
from terminal_render_forensics import analyze as terminal_analyze
from archive_intake_forensics import analyze as archive_analyze

def findings(o):return o.get("findings",[]) if isinstance(o,dict) else []
def scan(path):
    p=Path(path);ext=p.suffix.lower();analyses={}
    if ext==".docx":analyses["document_font"]=analyze_docx(p)
    elif ext==".pdf":analyses["document_font"]=analyze_pdf(p)
    elif ext in (".html",".htm"):analyses["document_font"]=analyze_html(p)
    elif ext in (".ttf",".otf",".woff",".woff2"):
        from evil_font_forensics import analyze_font_bytes
        analyses["font"]={"findings":analyze_font_bytes(p.read_bytes(),p.name).get("findings",[])}
    elif ext in (".zip",".tar",".tgz",".gz",".whl",".jar",".vsix"):
        try:analyses["archive"]=archive_analyze(p)
        except Exception as e:analyses["archive"]={"findings":[{"type":"archive_parse_failure","severity":"high","error":repr(e)}]}
    if ext in (".txt",".md",".markdown",".html",".htm",".xml",".json",".jsonl",".csv",".yaml",".yml"):
        text=p.read_text(encoding="utf-8",errors="replace")
        analyses["unicode"]=unicode_analyze(text)
        analyses["terminal"]=terminal_analyze(text)
        if ext in (".md",".markdown",".html",".htm"):
            analyses["markup"]=markup_analyze(text)
    fs=[]
    for domain,obj in analyses.items():
        for x in findings(obj):fs.append({"domain":domain,**x})
    sev={str(x.get("severity","")).lower() for x in fs}
    verdict="QUARANTINE" if "critical" in sev else ("REVIEW" if "high" in sev else "PASS")
    return {"schema":"ai-dfir/content-intake/v1.2","path":str(p.resolve()),"verdict":verdict,
            "findings":fs,"analyses":analyses,
            "rule":"PASS is not proof of safety; it means no modeled deterministic representation signal was detected."}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();obj=scan(a.path);s=json.dumps(obj,indent=2,sort_keys=True,default=str)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
    raise SystemExit({"PASS":0,"REVIEW":1,"QUARANTINE":2}[obj["verdict"]])
if __name__=="__main__":main()
