#!/usr/bin/env python3
"""Validate synthetic fixture coverage for every AI-DFIR Evidence Pack."""
from __future__ import annotations
import json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(ROOT))
from evidence_pack_engine import load_packs,assess
from generate_test_corpus import generate_pack_fixtures,slug

def main():
    manifest=HERE/'fixtures/EVIDENCE_PACK_FIXTURE_MANIFEST.json'
    if not manifest.exists():generate_pack_fixtures()
    failures=[];rows=[]
    for p in load_packs():
        case=HERE/'fixtures/evidence_packs'/slug(p['id']);a=assess(p,case)
        ok=a['mandatory_present']==a['mandatory_total']
        rows.append({'pack_id':p['id'],'mandatory':a['mandatory_total'],'qualified':a['mandatory_present'],'pass':ok})
        if not ok:
            failures.append({'pack_id':p['id'],'artifacts':[x for x in a['artifacts'] if x.get('priority')=='mandatory' and x.get('quality') not in ('VALIDATED','CORRELATED','AUTHORITATIVE')]})
    out={'schema':'ai-dfir/evidence-pack-matrix-test/v1.6','pack_count':len(rows),'passed':len(rows)-len(failures),'failed':len(failures),'status':'PASS' if not failures else 'FAIL','results':rows,'failures':failures}
    (HERE/'fixtures/EVIDENCE_PACK_MATRIX_RESULT.json').write_text(json.dumps(out,indent=2,sort_keys=True))
    print(json.dumps({'status':out['status'],'pack_count':len(rows),'passed':out['passed'],'failed':out['failed']},indent=2))
    if failures:raise SystemExit(2)
if __name__=='__main__':main()
