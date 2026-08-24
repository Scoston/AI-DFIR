#!/usr/bin/env python3
"""Deterministic export redaction with source-hash preservation and redaction manifest."""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
PATTERNS={'email':re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),'ipv4':re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),'bearer':re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}'),'api_key':re.compile(r'(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*["\']?([A-Za-z0-9._~+/=-]{8,})')}
def sha(b):return hashlib.sha256(b).hexdigest()
def redact(text,types):
    counts={};out=text
    for typ in types:
        pat=PATTERNS[typ];n=0
        def sub(m):
            nonlocal n;n+=1;return f'[REDACTED:{typ}:{hashlib.sha256(m.group(0).encode()).hexdigest()[:12]}]'
        out=pat.sub(sub,out);counts[typ]=n
    return out,counts
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--out',required=True);ap.add_argument('--type',action='append',choices=sorted(PATTERNS),default=[]);ap.add_argument('--manifest',required=True)
    a=ap.parse_args();src=Path(a.input).read_bytes();txt=src.decode('utf-8',errors='replace');types=a.type or ['bearer','api_key','email'];out,counts=redact(txt,types);Path(a.out).write_text(out)
    m={'schema':'ai-dfir/redaction-manifest/v1.4','source_sha256':sha(src),'redacted_sha256':sha(out.encode()),'types':types,'counts':counts,'source_path':str(Path(a.input).resolve()),'redacted_path':str(Path(a.out).resolve())};Path(a.manifest).write_text(json.dumps(m,indent=2,sort_keys=True));print(json.dumps(m,indent=2,sort_keys=True))
if __name__=='__main__':main()
