#!/usr/bin/env python3
"""Method-agnostic human-visible vs machine-readable text differential."""
from __future__ import annotations
import argparse, hashlib, json, re, unicodedata
from difflib import SequenceMatcher
from pathlib import Path

def norm(s):
    s=unicodedata.normalize("NFKC",s or "")
    return " ".join(s.split())
def tokens(s):return re.findall(r"\w+|[^\w\s]",norm(s),flags=re.UNICODE)
def analyze(machine,visible,source_machine=None,source_visible=None):
    mt,vt=tokens(machine),tokens(visible)
    ratio=SequenceMatcher(None,mt,vt,autojunk=False).ratio() if mt or vt else 1.0
    # A second character-level score helps on per-character glyph remapping.
    cr=SequenceMatcher(None,norm(machine),norm(visible),autojunk=False).ratio() if machine or visible else 1.0
    findings=[]
    divergence=1-min(ratio,cr)
    if divergence>=0.35 and max(len(mt),len(vt))>=8:
        findings.append({"type":"human_machine_representation_divergence","severity":"critical",
                         "token_similarity":round(ratio,4),"character_similarity":round(cr,4),
                         "divergence":round(divergence,4)})
    elif divergence>=0.15 and max(len(mt),len(vt))>=8:
        findings.append({"type":"human_machine_representation_divergence","severity":"high",
                         "token_similarity":round(ratio,4),"character_similarity":round(cr,4),
                         "divergence":round(divergence,4)})
    return {"schema":"ai-dfir/representation-differential/v1.2",
            "machine_text_sha256":hashlib.sha256((machine or "").encode()).hexdigest(),
            "visible_text_sha256":hashlib.sha256((visible or "").encode()).hexdigest(),
            "machine_source":source_machine,"visible_source":source_visible,
            "machine_chars":len(machine or ""),"visible_chars":len(visible or ""),
            "token_similarity":round(ratio,4),"character_similarity":round(cr,4),
            "findings":findings,
            "rule":"Visible text should come from an independent rendering/vision pipeline when available; this module performs comparison only."}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--machine",required=True);ap.add_argument("--visible",required=True)
    ap.add_argument("--machine-source");ap.add_argument("--visible-source");ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(Path(a.machine).read_text(encoding="utf-8",errors="replace"),
                                  Path(a.visible).read_text(encoding="utf-8",errors="replace"),
                                  a.machine_source or a.machine,a.visible_source or a.visible)
    s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
