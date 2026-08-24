#!/usr/bin/env python3
"""Detect terminal ANSI/OSC control-sequence deception in agent output."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

ESC="\x1b"
CSI=re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC=re.compile(r"\x1b\]([0-9]+);(.*?)(?:\x07|\x1b\\)",re.S)
DANGEROUS_CSI_FINAL=set("ABCDHfJKsu")
def analyze(text):
    findings=[];csi=CSI.findall(text);osc=[m.groups() for m in OSC.finditer(text)]
    dangerous=[x for x in csi if x and x[-1] in DANGEROUS_CSI_FINAL]
    if dangerous:findings.append({"type":"terminal_cursor_or_display_control","severity":"high","count":len(dangerous),"examples":dangerous[:20]})
    for code,payload in osc:
        if code=="8":
            findings.append({"type":"terminal_osc8_hyperlink","severity":"high","payload_sha256":__import__("hashlib").sha256(payload.encode()).hexdigest()})
        elif code=="52":
            findings.append({"type":"terminal_osc52_clipboard_control","severity":"critical","payload_sha256":__import__("hashlib").sha256(payload.encode()).hexdigest()})
        elif code in ("0","1","2"):
            findings.append({"type":"terminal_title_control","severity":"medium","osc":code})
        else:
            findings.append({"type":"terminal_osc_sequence","severity":"medium","osc":code})
    if ESC in text and not (csi or osc):
        findings.append({"type":"unparsed_terminal_escape_sequence","severity":"medium"})
    return {"schema":"ai-dfir/terminal-render-analysis/v1.2","csi_count":len(csi),"osc_count":len(osc),"findings":findings,
            "rule":"Analyzer surfaces control sequences; it never renders or interprets them in a terminal."}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(Path(a.path).read_text(encoding="utf-8",errors="replace"))
    s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
