#!/usr/bin/env python3
"""Verify deterministic evidence-redaction output against its source/manfiest."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from evidence_redaction import redact

def sha(b):return hashlib.sha256(b).hexdigest()
def validate(source,redacted,manifest):
    src=Path(source).read_bytes();red=Path(redacted).read_bytes();m=json.loads(Path(manifest).read_text());findings=[]
    if sha(src)!=m.get('source_sha256'):findings.append({'type':'redaction_source_hash_mismatch','severity':'critical'})
    if sha(red)!=m.get('redacted_sha256'):findings.append({'type':'redaction_output_hash_mismatch','severity':'critical'})
    text=src.decode('utf-8',errors='replace');expected,counts=redact(text,m.get('types') or [])
    if expected.encode()!=red:findings.append({'type':'redaction_not_deterministically_reproducible','severity':'critical'})
    if counts!=m.get('counts'):findings.append({'type':'redaction_count_mismatch','severity':'high','expected':counts,'manifest':m.get('counts')})
    return {'schema':'ai-dfir/redaction-validation/v1.5','valid':not any(x['severity']=='critical' for x in findings),'source_sha256':sha(src),'redacted_sha256':sha(red),'findings':findings}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--redacted',required=True);ap.add_argument('--manifest',required=True);ap.add_argument('--out')
    a=ap.parse_args();o=validate(a.source,a.redacted,a.manifest);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
