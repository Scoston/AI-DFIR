#!/usr/bin/env python3
"""Independent peer-review/sign-off gate for high-impact forensic conclusions."""
from __future__ import annotations
import argparse,json
from pathlib import Path

def assess(conclusions,reviews):
    by={r.get('conclusion_id'):[] for r in reviews}
    for r in reviews:by.setdefault(r.get('conclusion_id'),[]).append(r)
    findings=[];status=[]
    for c in conclusions:
        cid=c['conclusion_id'];required=int(c.get('required_independent_reviews',2 if c.get('severity') in ('critical','high') else 1));author=c.get('author');valid=[]
        for r in by.get(cid,[]):
            if r.get('reviewer')==author:continue
            if r.get('decision') in ('approve','concur') and r.get('evidence_reviewed',False):valid.append(r)
        ok=len({r.get('reviewer') for r in valid})>=required
        status.append({'conclusion_id':cid,'required_reviews':required,'independent_approvals':len({r.get('reviewer') for r in valid}),'ready':ok})
        if not ok:findings.append({'type':'critical_conclusion_peer_review_incomplete','severity':'critical' if c.get('severity')=='critical' else 'high','conclusion_id':cid})
    return {'schema':'ai-dfir/peer-review-gate/v1.4','ready':not findings,'conclusions':status,'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--conclusions',required=True);ap.add_argument('--reviews',required=True);ap.add_argument('--out')
    a=ap.parse_args();c=json.loads(Path(a.conclusions).read_text());r=json.loads(Path(a.reviews).read_text());o=assess(c.get('conclusions',c),r.get('reviews',r));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['ready'] else 2)
if __name__=='__main__':main()
