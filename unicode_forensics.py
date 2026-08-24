#!/usr/bin/env python3
"""Unicode and representation-smuggling forensic scanner."""
from __future__ import annotations
import argparse, html, json, re, unicodedata
from collections import Counter
from pathlib import Path

RANGES={
 "tag": [(0xE0000,0xE007F)],
 "variation_selector":[(0xFE00,0xFE0F),(0xE0100,0xE01EF)],
 "private_use":[(0xE000,0xF8FF),(0xF0000,0xFFFFD),(0x100000,0x10FFFD)],
}
BIDI={0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069,0x200E,0x200F,0x061C}
ZERO={0x200B,0x200C,0x200D,0x2060,0xFEFF,0x00AD,0x034F,0x180E,0x2800,0x3164,0xFFA0}
DEPRECATED=set(range(0x206A,0x2070))
CONFUSABLE={"а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ј":"j","Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X"}

def category(cp):
    if cp in BIDI:return "bidi"
    if cp in ZERO:return "zero_width_or_invisible"
    if cp in DEPRECATED:return "deprecated_format"
    for k,rs in RANGES.items():
        if any(a<=cp<=b for a,b in rs):return k
    return None

def decode_tags(text):
    chars=[]
    for c in text:
        cp=ord(c)
        if 0xE0020<=cp<=0xE007E:chars.append(chr(cp-0xE0000))
        elif cp==0xE007F:chars.append("")
    return "".join(chars)

def scripts(word):
    out=set()
    for c in word:
        if not c.isalpha():continue
        n=unicodedata.name(c,"")
        if n:
            out.add(n.split()[0])
    return out

def analyze(text):
    hits=[];counts=Counter()
    runs=[];cur=[];curcat=None
    for i,c in enumerate(text):
        cp=ord(c);cat=category(cp)
        if cat:
            counts[cat]+=1;hits.append({"index":i,"codepoint":f"U+{cp:04X}","category":cat,"name":unicodedata.name(c,"UNKNOWN")})
        if cat==curcat and cat:cur.append(c)
        else:
            if curcat:runs.append({"category":curcat,"length":len(cur),"decoded":decode_tags("".join(cur)) if curcat=="tag" else None})
            cur=[c] if cat else [];curcat=cat
    if curcat:runs.append({"category":curcat,"length":len(cur),"decoded":decode_tags("".join(cur)) if curcat=="tag" else None})
    nfkc=unicodedata.normalize("NFKC",text)
    findings=[]
    for cat,n in counts.items():
        sev="critical" if cat in ("tag","bidi") else "high"
        findings.append({"type":f"unicode_{cat}","severity":sev,"count":n})
    if nfkc!=text:
        findings.append({"type":"unicode_nfkc_normalization_delta","severity":"medium",
                         "original_sha256":__import__("hashlib").sha256(text.encode()).hexdigest(),
                         "nfkc_sha256":__import__("hashlib").sha256(nfkc.encode()).hexdigest()})
    conf=[{"char":c,"maps_to":CONFUSABLE[c],"index":i} for i,c in enumerate(text) if c in CONFUSABLE]
    if conf:findings.append({"type":"unicode_confusable_characters","severity":"high","count":len(conf),"examples":conf[:30]})
    mixed=[]
    for w in re.findall(r"\w+",text,flags=re.UNICODE):
        sc=scripts(w)
        if len(sc)>1:mixed.append({"word":w,"scripts":sorted(sc)})
    if mixed:findings.append({"type":"mixed_script_tokens","severity":"high","count":len(mixed),"examples":mixed[:20]})
    return {"schema":"ai-dfir/unicode-representation-analysis/v1.2","length":len(text),
            "counts":dict(counts),"runs":runs,"hits":hits[:500],"findings":findings,
            "tag_payloads":[r["decoded"] for r in runs if r["category"]=="tag" and r.get("decoded")]}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();text=Path(a.path).read_text(encoding="utf-8",errors="replace");obj=analyze(text)
    s=json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=False)
    if a.out:Path(a.out).write_text(s,encoding="utf-8")
    else:print(s)
if __name__=="__main__":main()
