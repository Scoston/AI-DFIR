#!/usr/bin/env python3
"""AI-DFIR v0.8 Evidence Pack Engine."""
from __future__ import annotations
import argparse, fnmatch, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
DEFAULT_PACK_ROOT=HERE/'evidence_packs'

def load_packs(root=DEFAULT_PACK_ROOT):
    packs=[]
    for p in sorted(Path(root).rglob('*.json')):
        try:
            obj=json.loads(p.read_text(encoding='utf-8'))
            if obj.get('schema') in ('ai-dfir/evidence-pack/v0.8','ai-dfir/evidence-pack/v0.9','ai-dfir/evidence-pack/v1.1','ai-dfir/evidence-pack/v1.2','ai-dfir/evidence-pack/v1.3','ai-dfir/evidence-pack/v1.4','ai-dfir/evidence-pack/v1.5','ai-dfir/evidence-pack/v1.6'):
                obj['_path']=str(p);packs.append(obj)
        except Exception:continue
    return packs

def catalog(root=DEFAULT_PACK_ROOT):
    return [{'id':p['id'],'title':p['title'],'vendor':p.get('vendor'),'platform':p.get('platform'),
             'incident_type':p.get('incident_type'),'alert_ids':p.get('match',{}).get('alert_ids',[]),
             'alert_titles':p.get('match',{}).get('alert_titles',[]),'forensic_modes':p.get('forensic_modes',[])}
            for p in load_packs(root)]

def get_pack(pack_id,root=DEFAULT_PACK_ROOT):
    for p in load_packs(root):
        if p.get('id')==pack_id:return p
    raise KeyError(pack_id)

def _norm(s):return (s or '').strip().lower()

def resolve(alert_id=None,alert_title=None,platform=None,incident_type=None,agent=None,root=DEFAULT_PACK_ROOT):
    scored=[]
    for p in load_packs(root):
        m=p.get('match',{});score=0;why=[]
        if alert_id and alert_id in (m.get('alert_ids') or []):score+=100;why.append('alert_id')
        if alert_title and any(_norm(alert_title)==_norm(x) for x in (m.get('alert_titles') or [])):
            score+=80;why.append('alert_title_exact')
        elif alert_title and any(_norm(x) in _norm(alert_title) or _norm(alert_title) in _norm(x) for x in (m.get('alert_titles') or [])):
            score+=50;why.append('alert_title_partial')
        if platform and (_norm(platform)==_norm(p.get('platform')) or any(_norm(platform)==_norm(x) for x in (m.get('platforms') or []))):
            score+=30;why.append('platform')
        incident_values=[_norm(p.get('incident_type'))]+[_norm(x) for x in (m.get('incident_types') or [])]
        if incident_type and _norm(incident_type) in incident_values:score+=35;why.append('incident_type')
        if agent and any(_norm(agent)==_norm(x) for x in (m.get('agents') or [])):score+=25;why.append('agent')
        if alert_title and any(_norm(x) in _norm(alert_title) for x in (m.get('detection_families') or [])):
            score+=20;why.append('detection_family')
        if score:scored.append({'score':score,'why':why,'pack':p})
    scored.sort(key=lambda x:(x['score'],x['pack']['id']),reverse=True);return scored

def relative_files(case_root:Path):
    out=[]
    for p in sorted(case_root.rglob('*')):
        if p.is_file():
            try:rel=str(p.relative_to(case_root)).replace('\\','/')
            except Exception:rel=str(p)
            out.append((p,rel))
    return out

def match_artifact(case_root:Path,artifact):
    matches=[];patterns=artifact.get('presence_patterns') or []
    for p,rel in relative_files(case_root):
        for pat in patterns:
            if fnmatch.fnmatch(rel.lower(),pat.lower()) or fnmatch.fnmatch(p.name.lower(),pat.lower()):
                matches.append(rel);break
    return sorted(set(matches))

def _gate_status(gate,status_by_id):
    aliases=gate.get('allow_aliases') or {}
    def has(req):
        if status_by_id.get(req,{}).get('status')=='present':return True
        return any(status_by_id.get(x,{}).get('status')=='present' for x in aliases.get(req,[]))
    reqs=gate.get('requires') or []
    if not reqs:return 'unknown',[]
    hits=[r for r in reqs if has(r)]
    ok=bool(hits) if gate.get('logic','all')=='any' else len(hits)==len(reqs)
    missing=[r for r in reqs if not has(r)]
    return ('supported' if ok else 'not_supported'),missing

def assess(pack,case_root:Path):
    # v1.1 delegates sufficiency to evidence-quality validation instead of
    # treating a filename/glob match as sufficient forensic evidence.
    from evidence_quality import assess_pack
    a=assess_pack(pack,case_root)
    # Backward-compatible aliases used by v0.8-v1.0 workbench code.
    a['schema']='ai-dfir/evidence-assessment/v1.1'
    a['mandatory_present']=a['mandatory_qualified']
    a['mandatory_complete']=a['mandatory_qualified']==a['mandatory_total']
    a['conditional_total']=sum(1 for x in a['artifacts'] if x.get('priority')=='conditional')
    a['vendor']=pack.get('vendor');a['platform']=pack.get('platform')
    a['incident_type']=pack.get('incident_type');a['forensic_modes']=pack.get('forensic_modes',[])
    a['questions']=pack.get('questions',[]);a['sources']=pack.get('sources',[]);a['notes']=pack.get('notes',[])
    return a


def markdown(a):
    lines=[f"# Evidence Pack — {a['pack_title']}",'',f"- Pack: `{a['pack_id']}`",
           f"- Vendor/platform: **{a.get('vendor')} / {a.get('platform')}**",
           f"- Mandatory evidence meeting `{a.get('mandatory_min_quality','VALIDATED')}`: **{a['mandatory_present']}/{a['mandatory_total']} ({a['mandatory_percent']}%)**",'',
           '## Artifact checklist','',
           '| Priority | Artifact | Presence | Quality | Matches / likely locations | Why it matters |',
           '|---|---|---|---|---|---|']
    for x in a['artifacts']:
        where=', '.join(x.get('matches') or x.get('locations') or [])
        lines.append(f"| {x.get('priority')} | {x.get('title')} | **{x.get('status','').upper()}** | **{x.get('quality','UNKNOWN')}** | {where.replace('|','/')} | {x.get('rationale','').replace('|','/')} |")
    lines += ['','## Conclusion gates','']
    for g in a['conclusion_gates']:
        extra=[]
        if g.get('missing'):extra.append("missing: "+', '.join(g['missing']))
        if g.get('insufficient_quality'):
            extra.append("quality: "+'; '.join(f"{x['artifact']} needs {x['required_quality']}" for x in g['insufficient_quality']))
        lines.append(f"- **{g['title']}** — `{g['status']}`"+(f" — {'; '.join(extra)}" if extra else ''))
    lines += ['','## Investigation questions','']+[f"- {q}" for q in a.get('questions',[])]
    if a.get('notes'):lines += ['','## Caveats','']+[f"- {n}" for n in a['notes']]
    lines += ['','> Presence alone is not forensic sufficiency. Missing, stale, conflicting, incomplete, or unvalidated evidence must not be interpreted as benign activity.','']
    return '\n'.join(lines)


def create_profile(case_root,pack_id,alert_id=None,alert_title=None,agent=None,root=DEFAULT_PACK_ROOT,additional_packs=None):
    p=get_pack(pack_id,root);obj={'schema':'ai-dfir/incident-profile/v1.6','evidence_pack_id':pack_id,'additional_evidence_pack_ids':sorted(set(additional_packs or [])),'alert_id':alert_id,'alert_title':alert_title,
        'agent':agent,'vendor':p.get('vendor'),'platform':p.get('platform'),'incident_type':p.get('incident_type')}
    out=Path(case_root)/'incident_profile.json';out.write_text(json.dumps(obj,indent=2,sort_keys=True));return out

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('catalog');p.add_argument('--pack-root',default=str(DEFAULT_PACK_ROOT))
    p=sp.add_parser('resolve');p.add_argument('--alert-id');p.add_argument('--alert-title');p.add_argument('--platform');p.add_argument('--incident-type');p.add_argument('--agent');p.add_argument('--pack-root',default=str(DEFAULT_PACK_ROOT))
    p=sp.add_parser('assess');p.add_argument('--pack',required=True);p.add_argument('--case',required=True);p.add_argument('--out');p.add_argument('--markdown');p.add_argument('--pack-root',default=str(DEFAULT_PACK_ROOT))
    p=sp.add_parser('profile');p.add_argument('--pack',required=True);p.add_argument('--additional-pack',action='append',default=[]);p.add_argument('--case',required=True);p.add_argument('--alert-id');p.add_argument('--alert-title');p.add_argument('--agent');p.add_argument('--pack-root',default=str(DEFAULT_PACK_ROOT))
    args=ap.parse_args()
    if args.cmd=='catalog':print(json.dumps(catalog(args.pack_root),indent=2,sort_keys=True))
    elif args.cmd=='resolve':
        rows=resolve(args.alert_id,args.alert_title,args.platform,args.incident_type,args.agent,args.pack_root)
        print(json.dumps([{'score':x['score'],'why':x['why'],'id':x['pack']['id'],'title':x['pack']['title']} for x in rows],indent=2))
    elif args.cmd=='assess':
        a=assess(get_pack(args.pack,args.pack_root),Path(args.case));txt=json.dumps(a,indent=2,sort_keys=True)
        if args.out:Path(args.out).write_text(txt)
        else:print(txt)
        if args.markdown:Path(args.markdown).write_text(markdown(a))
    else:print(create_profile(args.case,args.pack,args.alert_id,args.alert_title,args.agent,args.pack_root,args.additional_pack))
if __name__=='__main__':main()
