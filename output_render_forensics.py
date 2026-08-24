#!/usr/bin/env python3
"""Static AI output-rendering/active-content forensic analyzer. Never executes content."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from urllib.parse import urlparse

URL_RE=re.compile(r"(?i)(?:https?|wss?)://[^\s\"'<>)]{3,}")
DANGEROUS=[
 ("script_tag",re.compile(r"(?i)<\s*script\b")),
 ("iframe",re.compile(r"(?i)<\s*iframe\b")),
 ("javascript_url",re.compile(r"(?i)javascript\s*:")),
 ("event_handler",re.compile(r"(?i)\bon(?:load|error|click|mouseover|focus)\s*=")),
 ("svg_scriptable",re.compile(r"(?i)<\s*svg\b")),
]

def read(path):
    return Path(path).read_text(encoding="utf-8",errors="replace") if path else ""

def urls(text):return sorted(set(x.rstrip(".,") for x in URL_RE.findall(text or "")))

def analyze(raw,sanitized,rendered,network_events=None,approved_origins=None):
    approved=set(approved_origins or []);findings=[]
    layers={"raw":raw,"sanitized":sanitized,"rendered":rendered}
    layer_hits={}
    for name,text in layers.items():
        hits=[]
        for typ,pat in DANGEROUS:
            if pat.search(text):hits.append(typ)
        layer_hits[name]={"dangerous_constructs":hits,"urls":urls(text)}
    if layer_hits["sanitized"]["dangerous_constructs"]:
        findings.append({"type":"active_content_survived_sanitization","severity":"critical",
                         "constructs":layer_hits["sanitized"]["dangerous_constructs"]})
    if set(layer_hits["rendered"]["urls"])-set(layer_hits["sanitized"]["urls"]):
        findings.append({"type":"renderer_introduced_external_url","severity":"high",
                         "urls":sorted(set(layer_hits["rendered"]["urls"])-set(layer_hits["sanitized"]["urls"]))})
    for e in network_events or []:
        u=e.get("url");origin=None
        if u:
            x=urlparse(u);origin=f"{x.scheme}://{x.netloc}" if x.scheme and x.netloc else None
        if origin and approved and origin not in approved:
            findings.append({"type":"rendered_content_unapproved_network_request","severity":"high","origin":origin,"event":e})
        if (e.get("metadata") or {}).get("session_token_access"):
            findings.append({"type":"rendered_content_session_token_access","severity":"critical","event":e})
    return {"schema":"ai-dfir/output-render-analysis/v1.1","layers":layer_hits,"findings":findings,
            "rule":"Content is analyzed statically; this tool never renders or executes supplied HTML/Markdown."}

def load_jsonl(p):
    if not p:return []
    out=[]
    for line in Path(p).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--raw",required=True);ap.add_argument("--sanitized");ap.add_argument("--rendered")
    ap.add_argument("--network-log");ap.add_argument("--approved-origin",action="append",default=[]);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(read(a.raw),read(a.sanitized),read(a.rendered),load_jsonl(a.network_log),a.approved_origin)
    text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
