#!/usr/bin/env python3
"""Static hidden-source and rendered-source mismatch analyzer for HTML/Markdown."""
from __future__ import annotations
import argparse, html, json, re
from pathlib import Path
from urllib.parse import urlparse

PATTERNS=[
 ("html_comment",re.compile(r"<!--(.*?)-->",re.S)),
 ("markdown_reference_definition",re.compile(r"(?m)^\s*\[[^\]]+\]:\s+\S+.*$")),
 ("collapsed_details",re.compile(r"<details\b[^>]*>(.*?)</details>",re.I|re.S)),
 ("css_display_none",re.compile(r"display\s*:\s*none",re.I)),
 ("css_visibility_hidden",re.compile(r"visibility\s*:\s*hidden",re.I)),
 ("css_opacity_zero",re.compile(r"opacity\s*:\s*0(?:[;\s\"']|$)",re.I)),
 ("css_font_zero",re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem|%)?",re.I)),
 ("offscreen_css",re.compile(r"(?:left|top)\s*:\s*-\d{3,}(?:px|em|rem)",re.I)),
 ("aria_or_alt_instruction_channel",re.compile(r"(?:aria-label|alt)\s*=\s*[\"'][^\"']{40,}[\"']",re.I)),
]
MD_IMG=re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
HTML_SRC=re.compile(r"""(?i)(?:src|href)\s*=\s*["']([^"']+)["']""")

def analyze(text):
    findings=[];hidden=[]
    for typ,pat in PATTERNS:
        ms=list(pat.finditer(text))
        if ms:
            sev="critical" if typ in ("html_comment","css_display_none","css_visibility_hidden","css_opacity_zero","css_font_zero","offscreen_css") else "high"
            findings.append({"type":typ,"severity":sev,"count":len(ms)})
            for m in ms[:50]:hidden.append({"type":typ,"start":m.start(),"sha256":__import__("hashlib").sha256(m.group(0).encode()).hexdigest(),"length":len(m.group(0))})
    urls=MD_IMG.findall(text)+HTML_SRC.findall(text)
    extern=[]
    for u in urls:
        try:
            x=urlparse(html.unescape(u))
            if x.scheme in ("http","https","ws","wss"):
                extern.append({"url":u,"origin":f"{x.scheme}://{x.netloc}"})
        except Exception:pass
    if extern:findings.append({"type":"renderable_external_resources","severity":"medium","count":len(extern),"examples":extern[:25]})
    # Hex/entity-encoded comment content is surfaced as a representation mismatch lead.
    entity_delta=html.unescape(text)
    if entity_delta!=text:
        findings.append({"type":"html_entity_decoding_delta","severity":"medium"})
    return {"schema":"ai-dfir/markup-representation-analysis/v1.2","findings":findings,
            "hidden_regions":hidden,"external_resources":extern,
            "source_sha256":__import__("hashlib").sha256(text.encode()).hexdigest(),
            "decoded_source_sha256":__import__("hashlib").sha256(entity_delta.encode()).hexdigest()}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(Path(a.path).read_text(encoding="utf-8",errors="replace"))
    s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
