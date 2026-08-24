#!/usr/bin/env python3
"""Offline release integrity verification for AI-DFIR v1.6 artifacts."""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def parse_sums(p):
    out={}
    for line in Path(p).read_text().splitlines():
        m=re.match(r'^([0-9a-fA-F]{64})\s+\*?(.+)$',line.strip())
        if m:out[m.group(2)]=m.group(1).lower()
    return out

def verify(root,checksums,manifest=None,sbom=None,provenance=None):
    root=Path(root);findings=[];sums=parse_sums(checksums);checked=[]
    for rel,expected in sums.items():
        p=root/rel
        if not p.exists():findings.append({'type':'release_artifact_missing','severity':'critical','path':rel});continue
        actual=sha(p);checked.append({'path':rel,'sha256':actual})
        if actual!=expected:findings.append({'type':'release_checksum_mismatch','severity':'critical','path':rel,'expected':expected,'actual':actual})
    if manifest:
        m=json.loads(Path(manifest).read_text());
        for e in m.get('files',[]):
            p=root/e['path']
            if p.exists() and sha(p)!=e.get('sha256'):findings.append({'type':'package_manifest_hash_mismatch','severity':'critical','path':e['path']})
    if sbom:
        s=json.loads(Path(sbom).read_text());
        if s.get('bomFormat')!='CycloneDX':findings.append({'type':'sbom_format_invalid','severity':'high'})
    prov_status='NOT_SUPPLIED'
    if provenance:
        prov_status='STRUCTURE_ONLY'
        text=Path(provenance).read_text(encoding='utf-8',errors='replace').strip();objs=[]
        for line in text.splitlines():
            try:objs.append(json.loads(line))
            except Exception:pass
        subjects=[]
        for o in objs:
            pred=o.get('subject') or ((o.get('payload') or {}).get('subject') if isinstance(o.get('payload'),dict) else None) or []
            subjects.extend(pred if isinstance(pred,list) else [])
        if not subjects:findings.append({'type':'slsa_provenance_subject_missing','severity':'high'})
        else:prov_status='SUBJECT_PRESENT_CRYPTOGRAPHIC_VERIFICATION_EXTERNAL'
    return {'schema':'ai-dfir/release-integrity/v1.6','valid':not any(x['severity']=='critical' for x in findings),'checked_artifacts':checked,'provenance_status':prov_status,'findings':findings,
            'rule':'Checksum/SBOM/provenance structure is verified locally. Sigstore/SLSA cryptographic identity verification should be enforced by CI/admission tooling.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--checksums',required=True);ap.add_argument('--manifest');ap.add_argument('--sbom');ap.add_argument('--provenance');ap.add_argument('--out');a=ap.parse_args();o=verify(a.root,a.checksums,a.manifest,a.sbom,a.provenance);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
