#!/usr/bin/env python3
"""Typed, evidence-backed causal graph for AI incident reconstruction."""
from __future__ import annotations
import argparse,json
from collections import defaultdict,deque
from pathlib import Path

EDGE_TYPES={'caused_by','derived_from','contains_content_from','authorized_by','delegated_by','scheduled_by','retrieved_from','transformed_from','routed_by','executed_by','correlated_with','contradicts'}
CAUSAL={'caused_by','derived_from','contains_content_from','authorized_by','delegated_by','scheduled_by','retrieved_from','transformed_from','routed_by','executed_by'}

def load(p):
    out=[]
    for line in Path(p).read_text(encoding='utf-8',errors='replace').splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def build(events):
    nodes={e.get('event_id'):e for e in events if e.get('event_id')};edges=[];findings=[]
    def add(src,dst,typ,evidence=None,confidence=1.0,origin='system'):
        if not src or not dst:return
        if typ not in EDGE_TYPES:findings.append({'type':'unknown_causal_edge_type','severity':'high','edge_type':typ,'source':src,'target':dst});return
        edges.append({'source':src,'target':dst,'type':typ,'evidence_ids':evidence or [dst],'confidence':float(confidence),'origin':origin})
    for e in events:
        eid=e.get('event_id');parent=e.get('parent_event_id')
        if parent:add(parent,eid,'caused_by',[parent,eid],.8,'normalized_parent')
        for c in e.get('cause_event_ids') or []:add(c,eid,'caused_by',[c,eid],1.0,'explicit_cause')
        for c in e.get('correlation_ids') or []:
            if c in nodes:add(c,eid,'correlated_with',[c,eid],.3,'explicit_correlation')
        m=e.get('metadata') or {}
        refs={'source_event_id':'derived_from','authorization_event_id':'authorized_by','delegation_event_id':'delegated_by','scheduled_by_event_id':'scheduled_by','retrieval_event_id':'retrieved_from','transform_event_id':'transformed_from','route_event_id':'routed_by','executor_event_id':'executed_by'}
        for field,typ in refs.items():
            if m.get(field):add(m[field],eid,typ,[m[field],eid],1.0,'metadata')
        for x in m.get('typed_edges') or []:add(x.get('source'),x.get('target') or eid,x.get('type'),x.get('evidence_ids'),x.get('confidence',1),x.get('origin','event'))
    return {'schema':'ai-dfir/typed-causal-graph/v1.4','nodes':nodes,'edges':edges,'findings':findings}

def paths(graph,source,target,causal_only=True,max_depth=20):
    adj=defaultdict(list)
    for e in graph['edges']:
        if causal_only and e['type'] not in CAUSAL:continue
        adj[e['source']].append(e)
    q=deque([(source,[])]);seen={(source,0)};out=[]
    while q:
        n,path=q.popleft()
        if len(path)>=max_depth:continue
        for e in adj.get(n,[]):
            np=path+[e]
            if e['target']==target:out.append(np);continue
            key=(e['target'],len(np))
            if key not in seen:seen.add(key);q.append((e['target'],np))
    return out

def analyze(events,claims=None):
    g=build(events);claim_results=[]
    for c in claims or []:
        ps=paths(g,c['source'],c['target'],c.get('causal_only',True),c.get('max_depth',20))
        claim_results.append({'claim_id':c.get('claim_id'),'source':c['source'],'target':c['target'],'supported':bool(ps),'path_count':len(ps),'paths':ps[:20]})
        if not ps:g['findings'].append({'type':'causal_claim_unsupported','severity':'high','claim_id':c.get('claim_id'),'source':c['source'],'target':c['target']})
    g['claims']=claim_results;return g

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--events',required=True);ap.add_argument('--claims');ap.add_argument('--out')
    a=ap.parse_args();claims=json.loads(Path(a.claims).read_text()) if a.claims else [];claims=claims.get('claims',claims) if isinstance(claims,dict) else claims
    o=analyze(load(a.events),claims);s=json.dumps(o,indent=2,sort_keys=True,default=str);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
