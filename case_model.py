#!/usr/bin/env python3
"""Normalize AI-DFIR v0.1-v0.6 artifacts into one analyst case view."""
from __future__ import annotations
import csv, hashlib, json, sqlite3
from evidence_pack_engine import get_pack, assess as assess_pack, resolve as resolve_pack
from pathlib import Path


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def read_jsonl(path: Path):
    rows=[]
    if not path or not path.exists(): return rows
    with path.open(encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.strip(): continue
            try: rows.append(json.loads(line))
            except Exception: pass
    return rows


def read_csv(path: Path):
    if not path or not path.exists(): return []
    try:
        with path.open(newline='', encoding='utf-8', errors='replace') as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def sha256_file(path: Path, chunk=8*1024*1024):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b=f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()


def find_first(root: Path, names):
    for name in names:
        matches=sorted(root.rglob(name), key=lambda p:(len(p.parts), str(p)))
        if matches: return matches[0]
    return None


def find_all(root: Path, name):
    return sorted(root.rglob(name), key=lambda p:str(p))


def _float(v):
    try:return float(v)
    except Exception:return None


def _int(v):
    try:return int(v)
    except Exception:return None


def summary(root: Path):
    meta_path=find_first(root,['case.json'])
    meta=read_json(meta_path,{}) if meta_path else {}
    correlation_path=find_first(root,['evidence_correlation.json','correlation.json'])
    correlation=read_json(correlation_path,{}) if correlation_path else {}
    execution_path=find_first(root,['EXECUTION_RESULT.json'])
    execution=read_json(execution_path,{}) if execution_path else {}
    consequences_path=find_first(root,['open_consequences.json'])
    consequences=read_json(consequences_path,{}) if consequences_path else {}
    timeline_path=find_first(root,['timeline.json'])
    timeline=read_json(timeline_path,{}) if timeline_path else {}
    divergence_path=find_first(root,['divergence_report.json'])
    divergence=read_json(divergence_path,{}) if divergence_path else {}
    runtime_findings_path=find_first(root,['runtime_findings.json','findings.json'])
    runtime_findings=read_json(runtime_findings_path,[]) if runtime_findings_path else []
    control_path=find_first(root,['containment.json'])
    control=read_json(control_path,{}) if control_path else {}
    cp=(control or {}).get('payload',{}) if isinstance(control,dict) else {}

    level=correlation.get('confidence_level')
    severity='unknown'
    if isinstance(level,int): severity={0:'unknown',1:'low',2:'medium',3:'high',4:'critical'}.get(level,'unknown')
    elif str(execution.get('status','')).startswith('CONTAINED'): severity='high'

    evidence={
        'timeline':bool(timeline_path), 'divergence':bool(divergence_path),
        'runtime_findings':bool(runtime_findings_path), 'correlation':bool(correlation_path),
        'containment_result':bool(execution_path), 'open_consequences':bool(consequences_path),
        'containment_control':bool(control_path),
        'tensor_metrics':bool(find_first(root,['tensor_metrics.csv'])),
        'low_rank_screen':bool(find_first(root,['low_rank_screen.csv'])),
        'live_attestation':bool(find_first(root,['events.jsonl'])),
    }
    return {
        'case_id':meta.get('case_id') or root.name,
        'root':str(root.resolve()),
        'created_utc':meta.get('created_utc'),
        'tool_version':meta.get('tool_version'),
        'confidence_level':level,
        'finding':correlation.get('finding'),
        'severity':severity,
        'containment_status':execution.get('status') or cp.get('mode'),
        'containment_mode':cp.get('mode'),
        'first_divergence_depth':divergence.get('first_material_divergence_depth'),
        'highest_anomaly_depth':divergence.get('highest_anomaly_depth'),
        'highest_abs_robust_z':divergence.get('highest_abs_robust_z'),
        'open_consequences':consequences.get('open_count'),
        'timeline_events':timeline.get('event_count'),
        'runtime_findings_count':len(runtime_findings) if isinstance(runtime_findings,list) else None,
        'evidence':evidence,
    }


def layers(root: Path):
    by={}
    anomaly=find_first(root,['anomaly_events.csv'])
    for r in read_csv(anomaly):
        try:d=int(r['depth']); z=float(r.get('abs_robust_z') or 0)
        except Exception:continue
        x=by.setdefault(d,{'depth':d,'max_abs_robust_z':0.0,'metrics':[],'anomalous':False})
        x['max_abs_robust_z']=max(x['max_abs_robust_z'],z)
        an=str(r.get('anomalous','')).lower()=='true'
        x['anomalous']=x['anomalous'] or an
        x['metrics'].append({'metric':r.get('metric'),'value':_float(r.get('value')),
                             'robust_z':_float(r.get('robust_z')),'anomalous':an})
    matched=find_first(root,['matched_activation_delta.csv'])
    for r in read_csv(matched):
        try:d=int(r['depth'])
        except Exception:continue
        x=by.setdefault(d,{'depth':d,'max_abs_robust_z':0.0,'metrics':[],'anomalous':False})
        x['mean_prompt_cosine_similarity']=_float(r.get('mean_prompt_cosine_similarity'))
        x['mean_relative_l2_delta']=_float(r.get('mean_relative_l2_delta'))
    return [by[k] for k in sorted(by)]


def tensors(root: Path, limit=250):
    metrics=read_csv(find_first(root,['tensor_metrics.csv']))
    low=read_csv(find_first(root,['low_rank_screen.csv']))
    low_by={r.get('tensor'):r for r in low}
    out=[]
    for r in metrics:
        try:rel=float(r.get('relative_fro_delta') or 0)
        except Exception:rel=0.0
        if r.get('status')!='compared' or rel<=0:continue
        lr=low_by.get(r.get('tensor'),{})
        out.append({'tensor':r.get('tensor'),'layer':_int(r.get('layer')),'component':r.get('component'),
                    'relative_fro_delta':rel,'changed_fraction':_float(r.get('changed_fraction')),
                    'top1_energy_ratio':_float(lr.get('top1_energy_ratio')),
                    'effective_rank':_float(lr.get('effective_rank'))})
    out.sort(key=lambda x:x['relative_fro_delta'], reverse=True)
    return out[:limit]


def runtime(root: Path):
    fp=find_first(root,['runtime_findings.json','findings.json'])
    findings=read_json(fp,[]) if fp else []
    if not isinstance(findings,list):findings=[]
    inv=[]
    for name in ['approved_runtime_inventory.json','suspect_runtime_inventory.json','model_runtime_inventory.json','approved.json','suspect.json']:
        for p in find_all(root,name):
            obj=read_json(p,{})
            if isinstance(obj,dict) and ('hooks' in obj or 'adapters' in obj):
                inv.append({'path':str(p.relative_to(root)),'model_class':obj.get('model_class'),
                            'parameter_count':obj.get('parameter_count'),'hooks':len(obj.get('hooks') or []),
                            'active_adapters':(obj.get('adapters') or {}).get('active_adapters'),
                            'config_sha256':obj.get('config_sha256')})
    return {'findings':findings,'inventories':inv}


def consequences(root: Path):
    p=find_first(root,['open_consequences.json'])
    if p:return read_json(p,{})
    trace=find_first(root,['trace.jsonl','agent_trace.jsonl'])
    es=read_jsonl(trace)
    cs=[e for e in es if e.get('event_type')=='consequence']
    return {'total_consequences':len(cs),'open_count':None,'open_consequences':cs}


def timeline(root: Path, limit=2000):
    p=find_first(root,['timeline.json'])
    if p:
        obj=read_json(p,{})
        return (obj.get('events') or [])[:limit]
    events=[]
    for name in ['containment_audit.jsonl','events.jsonl','trace.jsonl','agent_trace.jsonl']:
        for p in find_all(root,name):
            for e in read_jsonl(p):
                ts=e.get('timestamp_utc')
                if ts:events.append({'timestamp_utc':ts,'source':name,'event_type':e.get('event_type'),
                                     'summary':e.get('name') or e.get('status') or e.get('prompt_id') or '',
                                     'details':e})
    events.sort(key=lambda x:x.get('timestamp_utc',''))
    return events[:limit]


def authority_graph(root: Path):
    trace=find_first(root,['trace.jsonl','agent_trace.jsonl'])
    es=read_jsonl(trace)
    nodes={};edges=[]
    def node(uid,label,kind,extra=None):
        if uid and uid not in nodes:nodes[uid]={'id':uid,'label':label or uid,'kind':kind,**(extra or {})}
    for e in es:
        eid=e.get('event_id'); et=e.get('event_type') or 'event'; name=e.get('name') or et
        node(eid,name,et,{'timestamp_utc':e.get('timestamp_utc')})
        parent=e.get('parent_id')
        if parent:
            node(parent,parent,'parent');edges.append({'source':parent,'target':eid,'kind':'parent'})
        auth=e.get('authority_id')
        if auth:
            aid=f'authority:{auth}';node(aid,auth,'authority');edges.append({'source':aid,'target':eid,'kind':'authorizes'})
    return {'nodes':list(nodes.values()),'edges':edges}


def integrity(root: Path):
    items=[]
    for name in ['PACKAGE_MANIFEST_V0.7.json','PACKAGE_MANIFEST_V0.6.json','PACKAGE_MANIFEST_V0.5.json']:
        for p in find_all(root,name):
            obj=read_json(p,{}) or {}; verified=missing=mismatch=0
            for f in obj.get('files') or []:
                fp=p.parent/f['path']
                if not fp.exists():missing+=1;continue
                try:
                    if sha256_file(fp)==f.get('sha256'):verified+=1
                    else:mismatch+=1
                except Exception:mismatch+=1
            items.append({'type':'package_manifest','path':str(p.relative_to(root)),'verified':verified,
                          'missing':missing,'mismatch':mismatch,
                          'status':'PASS' if missing==0 and mismatch==0 else 'FAIL'})
    for p in find_all(root,'containment_audit.jsonl'):
        prev='0'*64;count=0;ok=True;error=None
        for line in p.read_text(encoding='utf-8').splitlines():
            if not line.strip():continue
            try:
                raw=json.loads(line); got=raw.pop('event_hash'); raw.pop('event_hmac_sha256',None)
                if raw.get('prev_event_hash')!=prev:ok=False;error='previous hash mismatch';break
                exp=hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                if got!=exp:ok=False;error='event hash mismatch';break
                prev=got;count+=1
            except Exception as e:ok=False;error=repr(e);break
        items.append({'type':'containment_audit_chain','path':str(p.relative_to(root)),
                      'event_count':count,'status':'PASS' if ok else 'FAIL','error':error})
    return items


def fleet(root: Path):
    # Prefer a captured JSON view, otherwise read a copied v0.5 fleet.db read-only.
    p=find_first(root,['fleet_state.json','fleet_snapshot.json'])
    if p:
        obj=read_json(p,{})
        if isinstance(obj,dict):return obj
    db=find_first(root,['fleet.db'])
    if not db:return {'nodes':[],'alerts':[]}
    nodes=[];alerts=[]
    try:
        uri='file:'+str(db.resolve())+'?mode=ro'
        c=sqlite3.connect(uri,uri=True,timeout=2);c.row_factory=sqlite3.Row
        try:
            nodes=[dict(r) for r in c.execute('SELECT * FROM node_state ORDER BY node_id')]
            for n in nodes:
                try:n['findings']=json.loads(n.pop('findings_json'))
                except Exception:n['findings']=[]
            alerts=[dict(r) for r in c.execute('SELECT id,node_id,seq,created_utc,severity,code,finding_json FROM alerts ORDER BY id DESC LIMIT 100')]
            for a in alerts:
                try:a['finding']=json.loads(a.pop('finding_json'))
                except Exception:a['finding']={}
        finally:c.close()
    except Exception as e:
        return {'nodes':[],'alerts':[],'error':repr(e),'db_path':str(db.relative_to(root))}
    return {'nodes':nodes,'alerts':alerts,'db_path':str(db.relative_to(root))}


def annotations(root: Path):
    p=find_first(root,['annotations.jsonl','analyst_annotations.jsonl'])
    rows=read_jsonl(p) if p else []
    out=[]
    for r in rows:
        env=r.get('envelope') or {};payload=env.get('payload') or {}
        if payload.get('schema')=='ai-dfir/analyst-annotation/v0.7':
            out.append({
                'annotation_id':payload.get('annotation_id'),
                'timestamp_utc':payload.get('timestamp_utc'),
                'author':payload.get('author'),
                'note':payload.get('note'),
                'evidence_ref':payload.get('evidence_ref'),
                'tags':payload.get('tags') or [],
                'record_hash':r.get('record_hash'),
                'key_id':env.get('key_id'),
            })
    return out


def containment(root: Path):
    rp=find_first(root,['EXECUTION_RESULT.json']); result=read_json(rp,{}) if rp else {}
    cp=find_first(root,['containment.json']); control=read_json(cp,{}) if cp else {}
    pp=find_first(root,['containment_plan.json']); plan=read_json(pp,{}) if pp else {}
    ap=find_first(root,['containment_audit.jsonl']); audit=read_jsonl(ap)
    return {'result':result,
            'control':control.get('payload',{}) if isinstance(control,dict) else {},
            'plan':plan.get('payload',{}) if isinstance(plan,dict) else {},
            'audit':audit}




def agentic(root: Path):
    def pick(names, default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    mcp=pick(['mcp_findings.json','mcp_analysis.json'],{})
    rag=pick(['rag_findings.json','rag_provenance.json'],{})
    memory=pick(['memory_lineage.json'],{})
    authority=pick(['authority_diff.json','effective_authority.json'],{})
    causal=pick(['causal_analysis.json','agentic_causal_analysis.json'],{})
    rules=pick(['agentic_rule_findings.json'],{})
    return {
        'mcp':mcp or {},
        'rag':rag or {},
        'memory':memory or {},
        'authority':authority or {},
        'causal':causal or {},
        'rules':rules or {},
        'presence':{
            'mcp':bool(mcp),'rag':bool(rag),'memory':bool(memory),
            'authority':bool(authority),'causal':bool(causal),'rules':bool(rules)
        }
    }



def execution_integrity(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    data={
      'harness':pick(['harness_findings.json','harness_lifecycle_analysis.json'],{}),
      'taint':pick(['taint_analysis.json'],{}),
      'browser':pick(['browser_analysis.json'],{}),
      'session_task':pick(['session_task_analysis.json'],{}),
      'a2a':pick(['a2a_event_analysis.json','a2a_card_findings.json'],{}),
      'router':pick(['router_analysis.json'],{}),
      'cache':pick(['cache_analysis.json'],{}),
      'replication':pick(['prompt_replication_analysis.json'],{}),
      'workspace':pick(['workspace_trust_findings.json','workspace_trust_diff.json'],{}),
      'rendering':pick(['output_render_analysis.json'],{}),
      'tool_identity':pick(['tool_identity_analysis.json'],{}),
      'mcp_execution':pick(['mcp_execution_integrity.json'],{}),
      'lifecycle':pick(['agent_lifecycle_analysis.json'],{}),
      'run':pick(['execution_integrity_run.json'],{}),
      'acquisition_manifest':pick(['ACQUISITION_MANIFEST.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    findings=[]
    for k,v in data.items():
        if not isinstance(v,dict):continue
        for x in v.get('findings') or []:
            if isinstance(x,dict):findings.append({'domain':k,**x})
    data['findings']=findings
    return data



def representation_integrity(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    data={
      'intake':pick(['content_intake_analysis.json'],{}),
      'document_font':pick(['evil_font_analysis.json','document_font_analysis.json'],{}),
      'differential':pick(['representation_differential.json'],{}),
      'unicode':pick(['unicode_analysis.json'],{}),
      'markup':pick(['markup_analysis.json'],{}),
      'terminal':pick(['terminal_analysis.json'],{}),
      'network_exfil':pick(['network_exfil_analysis.json'],{}),
      'approval':pick(['approval_integrity_analysis.json'],{}),
      'session_state':pick(['session_state_integrity.json'],{}),
      'ide_surface':pick(['ide_surface_diff.json'],{}),
      'run':pick(['representation_integrity_run.json'],{}),
      'acquisition_trust':pick(['ACQUISITION_TRUST.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    fs=[]
    for k,v in data.items():
        if not isinstance(v,dict):continue
        for x in v.get('findings') or []:
            if isinstance(x,dict):fs.append({'domain':k,**x})
        if k=='intake':
            for x in v.get('findings') or []:
                if isinstance(x,dict):fs.append({'domain':'intake',**x})
    data['findings']=fs
    return data



def a2a_trust(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    data={
      'verification':pick(['a2a_agent_card_verification.json'],{}),
      'history':pick(['a2a_card_history.json'],{}),
      'execution_binding':pick(['a2a_execution_binding.json'],{}),
      'run':pick(['a2a_trust_run.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    fs=[]
    for k,v in data.items():
        if isinstance(v,dict):
            for x in v.get('findings') or []:
                if isinstance(x,dict):fs.append({'domain':k,**x})
            for sig in v.get('signatures') or []:
                for x in sig.get('findings') or []:
                    if isinstance(x,dict):fs.append({'domain':'signature',**x})
    data['findings']=fs
    return data



def runtime_trust(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    data={
      'workload_identity':pick(['workload_identity_analysis.json'],{}),
      'credential_lineage':pick(['credential_lineage_analysis.json'],{}),
      'temporal_authority':pick(['temporal_authority_analysis.json'],{}),
      'memory_integrity':pick(['memory_integrity_analysis.json'],{}),
      'skill_supply_chain':pick(['skill_supply_chain_diff.json'],{}),
      'mcp_2026':pick(['mcp_2026_forensics.json'],{}),
      'otel_genai':pick(['otel_genai_ingest.json'],{}),
      'causal_graph':pick(['typed_causal_graph.json'],{}),
      'collector_health':pick(['collector_health.json'],{}),
      'transparency':pick(['transparency_validation.json'],{}),
      'behavioral_sandbox':pick(['behavioral_sandbox_analysis.json'],{}),
      'analyst_audit':pick(['analyst_action_audit.json'],{}),
      'peer_review':pick(['peer_review_gate.json'],{}),
      'run':pick(['runtime_trust_run.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    fs=[]
    for k,v in data.items():
        if isinstance(v,dict):
            for x in v.get('findings') or []:
                if isinstance(x,dict):fs.append({'domain':k,**x})
    data['findings']=fs
    return data



def enterprise_v15(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    gaps=[]
    for p in find_all(root,'provider_evidence_gap*.json')+find_all(root,'*provider_gap*.json'):
        obj=read_json(p,{})
        if obj and obj not in gaps:gaps.append(obj)
    receipts=[]
    for p in find_all(root,'*.receipt.json'):
        obj=read_json(p,{})
        if isinstance(obj,dict) and obj.get('schema') in ('ai-dfir/provider-collection-receipt/v1.5','ai-dfir/acquisition-receipt/v1.5'):
            receipts.append(obj)
    data={
      'production_readiness':pick(['production_readiness_v15.json','production_readiness.json'],{}),
      'provider_gaps':gaps,
      'provider_receipts':receipts,
      'oidc_identity':pick(['oidc_principal.json','oidc_identity.json'],{}),
      'spiffe_identity':pick(['spiffe_identity.json','spiffe_mtls_identity.json'],{}),
      'object_store':pick(['object_store_verification.json'],{}),
      'dr_restore':pick(['dr_restore_validation.json'],{}),
      'service_slo':pick(['service_slo.json'],{}),
      'a2a_request_provenance':pick(['a2a_request_provenance.json'],{}),
      'case_export':pick(['case_export_validation.json','case_export.json'],{}),
      'scale_benchmark':pick(['scale_benchmark.json'],{}),
      'legal_hold':pick(['legal_hold_status.json','legal_hold.json'],{}),
      'distributed_acquisition':pick(['distributed_acquisition_status.json','collector_worker_result.json'],{}),
      'run':pick(['enterprise_v15_run.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    fs=[]
    for k,v in data.items():
        vals=v if isinstance(v,list) else [v]
        for item in vals:
            if isinstance(item,dict):
                for x in item.get('findings') or []:
                    if isinstance(x,dict):fs.append({'domain':k,**x})
    data['findings']=fs
    data['mandatory_provider_collection_complete']=bool(gaps) and all(x.get('complete_mandatory') is True for x in gaps)
    return data


def enterprise_v16(root: Path):
    def pick(names,default=None):
        p=find_first(root,names)
        return read_json(p,default) if p else default
    certs=[]
    for p in find_all(root,'*provider*certification*.json'):
        o=read_json(p,{})
        if isinstance(o,dict) and o not in certs:certs.append(o)
    data={
      'platform_assurance':pick(['platform_assurance_v16.json','platform_assurance.json'],{}),
      'provider_certifications':certs,
      'environment_separation':pick(['environment_separation.json'],{}),
      'chaos_validation':pick(['chaos_validation.json'],{}),
      'release_integrity':pick(['release_integrity.json'],{}),
      'security_assurance':pick(['security_assurance.json'],{}),
      'upgrade_assurance':pick(['upgrade_assurance.json'],{}),
      'network_policy_validation':pick(['network_policy_validation.json'],{}),
      'schema_migration':pick(['schema_migration.json'],{}),
      'run':pick(['enterprise_v16_run.json'],{}),
    }
    data['presence']={k:bool(v) for k,v in data.items() if k!='presence'}
    fs=[]
    for k,v in data.items():
        vals=v if isinstance(v,list) else [v]
        for item in vals:
            if isinstance(item,dict):
                for x in item.get('findings') or []:
                    if isinstance(x,dict):fs.append({'domain':k,**x})
    data['findings']=fs
    data['all_provider_certifications_current']=bool(certs) and all(x.get('certified') is True for x in certs)
    return data


def evidence_pack(root: Path):
    profile_path=find_first(root,['incident_profile.json'])
    profile=read_json(profile_path,{}) if profile_path else {}
    pack_id=profile.get('evidence_pack_id')
    resolution=None
    if not pack_id:
        alert_id=profile.get('alert_id'); alert_title=profile.get('alert_title')
        platform=profile.get('platform'); incident_type=profile.get('incident_type'); agent=profile.get('agent')
        if any([alert_id,alert_title,platform,incident_type,agent]):
            rows=resolve_pack(alert_id,alert_title,platform,incident_type,agent)
            if rows:
                resolution={'score':rows[0]['score'],'why':rows[0]['why']}
                pack_id=rows[0]['pack']['id']
    ids=[]
    if pack_id:ids.append(pack_id)
    ids += [x for x in (profile.get('additional_evidence_pack_ids') or []) if x not in ids]
    assessments=[]
    errors=[]
    for pid in ids:
        try:assessments.append(assess_pack(get_pack(pid),root))
        except Exception as e:errors.append({'pack_id':pid,'error':repr(e)})
    if not assessments:
        return {'selected':False,'profile':profile,'assessment':None,'assessments':[],
                'resolution':resolution,'errors':errors}
    primary=assessments[0]
    # Overall sufficiency is intentionally strict across all selected packs.
    mt=sum(x.get('mandatory_total',0) for x in assessments)
    mp=sum(x.get('mandatory_present',0) for x in assessments)
    return {'selected':True,'profile':profile,'assessment':primary,'assessments':assessments,
            'mandatory_present':mp,'mandatory_total':mt,
            'mandatory_percent':round((mp/mt*100) if mt else 100.0,1),
            'resolution':resolution,'errors':errors}


def evidence_coverage(root: Path):
    s=summary(root);ev=s['evidence'];total=len(ev);present=sum(1 for v in ev.values() if v)
    missing=[k for k,v in ev.items() if not v]
    return {'present':present,'total':total,'percent':round((present/total*100) if total else 0,1),'missing':missing}


def full_case(root: Path):
    root=root.resolve()
    return {'summary':summary(root),'coverage':evidence_coverage(root),'layers':layers(root),
            'tensors':tensors(root),'runtime':runtime(root),'consequences':consequences(root),
            'timeline':timeline(root),'authority_graph':authority_graph(root),
            'integrity':integrity(root),'containment':containment(root),'fleet':fleet(root),'annotations':annotations(root),
            'evidence_pack':evidence_pack(root),'agentic':agentic(root),'execution_integrity':execution_integrity(root),'representation_integrity':representation_integrity(root),'a2a_trust':a2a_trust(root),'runtime_trust':runtime_trust(root),'enterprise_v15':enterprise_v15(root),'enterprise_v16':enterprise_v16(root)}


def looks_like_case(path: Path):
    markers=['case.json','tensor_metrics.csv','divergence_report.json','EXECUTION_RESULT.json','timeline.json','containment_audit.jsonl']
    return any(list(path.rglob(m)) for m in markers)


def discover_cases(root: Path):
    root=root.resolve();cases=[]
    if looks_like_case(root):cases.append(root)
    else:
        for p in sorted([x for x in root.iterdir() if x.is_dir()]):
            if looks_like_case(p):cases.append(p)
    return cases


if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True);ap.add_argument('--out')
    a=ap.parse_args();obj=full_case(Path(a.case));text=json.dumps(obj,indent=2,sort_keys=True,default=str)
    Path(a.out).write_text(text) if a.out else print(text)
