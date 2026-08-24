#!/usr/bin/env python3
"""Compare expected provider evidence sources with acquired/healthy sources."""
from __future__ import annotations
import argparse,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def analyze(provider,available,unavailable=None,profiles=None):
    profiles=profiles or json.loads((HERE/'provider_native_sources_v15.json').read_text())
    p=profiles['providers'][provider];available=set(available or []);unavailable=unavailable or {}
    findings=[];status={}
    for src in p['mandatory']:
        if src in available:status[src]='PRESENT'
        elif src in unavailable:
            status[src]='UNAVAILABLE';findings.append({'type':'mandatory_provider_source_unavailable','severity':'critical','source':src,'reason':unavailable[src]})
        else:
            status[src]='MISSING';findings.append({'type':'mandatory_provider_source_missing','severity':'critical','source':src})
    for src in p.get('conditional',[]):status[src]='PRESENT' if src in available else ('UNAVAILABLE' if src in unavailable else 'NOT_COLLECTED')
    return {'schema':'ai-dfir/provider-evidence-gap/v1.5','provider':provider,'complete_mandatory':not any(x['severity']=='critical' for x in findings),'sources':status,'findings':findings,'provider_notes':p.get('notes',[])}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--provider',required=True);ap.add_argument('--available',action='append',default=[]);ap.add_argument('--unavailable-json');ap.add_argument('--out')
    a=ap.parse_args();o=analyze(a.provider,a.available,json.loads(Path(a.unavailable_json).read_text()) if a.unavailable_json else {});s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['complete_mandatory'] else 2)
if __name__=='__main__':main()
