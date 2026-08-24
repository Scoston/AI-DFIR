#!/usr/bin/env python3
import csv, hashlib, json, shutil, sys, threading, urllib.request, urllib.error, sqlite3
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from fleet_crypto import generate as generate_key
from analyst_annotations import add as add_annotation, verify as verify_annotations
from case_model import full_case
from case_search import search
from report_generator import generate as generate_report
from analyst_dashboard import App, Handler
from http.server import ThreadingHTTPServer


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def sha_tree(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        if p.is_file():
            rows.append([str(p.relative_to(root)),hashlib.sha256(p.read_bytes()).hexdigest()])
    return hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()


def audit_event(prev,event_type,ts,details):
    core={'schema':'ai-dfir/containment-audit/v0.6','timestamp_utc':ts,'event_type':event_type,
          'incident_id':'CASE-V07','details':details,'prev_event_hash':prev}
    h=hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {**core,'event_hash':h},h


def build_case(root):
    root.mkdir(parents=True,exist_ok=True)
    (root/'00_case').mkdir();(root/'00_case'/'case.json').write_text(json.dumps({
        'schema':'ai-dfir/case/v0.4','case_id':'CASE-V07','created_utc':'2026-08-23T20:00:00Z','tool_version':'0.7'
    }))
    (root/'16_reports').mkdir();(root/'16_reports'/'evidence_correlation.json').write_text(json.dumps({
        'confidence_level':4,'finding':'runtime-only model-behavior intervention','evidence':[{'signal':'activation_divergence'}]
    }))
    (root/'09_baselines'/'suspect_score').mkdir(parents=True)
    (root/'09_baselines'/'suspect_score'/'divergence_report.json').write_text(json.dumps({
        'first_material_divergence_depth':36,'highest_anomaly_depth':40,'highest_abs_robust_z':12.4,
        'flagged_depths':[36,40,44]
    }))
    write_csv(root/'09_baselines'/'suspect_score'/'anomaly_events.csv',
              ['request_id','prompt_id','depth','metric','value','baseline_median','baseline_mad','robust_z','abs_robust_z','scoring_method','anomalous'],[
        {'request_id':'r1','prompt_id':'p1','depth':24,'metric':'relative_l2_to_exact_approved_activation','value':'0.002','baseline_median':'0.002','baseline_mad':'0.0002','robust_z':'0','abs_robust_z':'0','scoring_method':'mad','anomalous':'False'},
        {'request_id':'r1','prompt_id':'p1','depth':36,'metric':'relative_l2_to_exact_approved_activation','value':'0.25','baseline_median':'0.002','baseline_mad':'0.0002','robust_z':'9.2','abs_robust_z':'9.2','scoring_method':'mad','anomalous':'True'},
        {'request_id':'r1','prompt_id':'p1','depth':40,'metric':'relative_l2_to_exact_approved_activation','value':'0.32','baseline_median':'0.002','baseline_mad':'0.0002','robust_z':'12.4','abs_robust_z':'12.4','scoring_method':'mad','anomalous':'True'},
    ])
    (root/'10_replay'/'comparison').mkdir(parents=True)
    write_csv(root/'10_replay'/'comparison'/'matched_activation_delta.csv',
              ['depth','mean_prompt_cosine_similarity','min_prompt_cosine_similarity','mean_relative_l2_delta','max_relative_l2_delta'],[
        {'depth':24,'mean_prompt_cosine_similarity':'0.999','min_prompt_cosine_similarity':'0.998','mean_relative_l2_delta':'0.002','max_relative_l2_delta':'0.003'},
        {'depth':36,'mean_prompt_cosine_similarity':'0.88','min_prompt_cosine_similarity':'0.82','mean_relative_l2_delta':'0.24','max_relative_l2_delta':'0.30'},
        {'depth':40,'mean_prompt_cosine_similarity':'0.71','min_prompt_cosine_similarity':'0.62','mean_relative_l2_delta':'0.35','max_relative_l2_delta':'0.42'},
    ])
    (root/'04_static_analysis').mkdir()
    write_csv(root/'04_static_analysis'/'tensor_metrics.csv',
              ['tensor','status','layer','component','relative_fro_delta','changed_fraction'],[
        {'tensor':'model.layers.36.linear_attn.out_proj.weight','status':'compared','layer':'36','component':'linear_attention','relative_fro_delta':'0.009','changed_fraction':'1.0'},
        {'tensor':'model.layers.40.mlp.down_proj.weight','status':'compared','layer':'40','component':'mlp','relative_fro_delta':'0.006','changed_fraction':'0.99'},
    ])
    write_csv(root/'04_static_analysis'/'low_rank_screen.csv',
              ['tensor','layer','top1_energy_ratio','effective_rank'],[
        {'tensor':'model.layers.36.linear_attn.out_proj.weight','layer':'36','top1_energy_ratio':'0.98','effective_rank':'1.1'},
        {'tensor':'model.layers.40.mlp.down_proj.weight','layer':'40','top1_energy_ratio':'0.95','effective_rank':'1.5'},
    ])
    (root/'01_runtime').mkdir()
    runtime_findings=[{'type':'unexpected_hook','hook':['model.layers.36','forward','abc','refusal_hook']},
                      {'type':'active_adapters_changed','approved':[],'suspect':['unknown_adapter']}]
    (root/'01_runtime'/'runtime_findings.json').write_text(json.dumps(runtime_findings))
    (root/'01_runtime'/'suspect_runtime_inventory.json').write_text(json.dumps({
        'model_class':'Qwen3_8ForConditionalGeneration','parameter_count':27000000000,
        'config_sha256':'suspect','hooks':[{'module_name':'model.layers.36'}],
        'adapters':{'active_adapters':['unknown_adapter']}
    }))
    (root/'11_agent_trace').mkdir()
    trace=[
        {'event_type':'decision','event_id':'dec1','timestamp_utc':'2026-08-23T20:00:01Z','name':'Evaluate account','authority_id':'role-analyst','metadata':{}},
        {'event_type':'tool_call','event_id':'tool1','timestamp_utc':'2026-08-23T20:00:02Z','name':'disable_user','authority_id':'role-analyst','parent_id':'dec1','content_sha256':'111','metadata':{}},
        {'event_type':'consequence','event_id':'cons1','timestamp_utc':'2026-08-23T20:00:03Z','name':'account_disabled','authority_id':'role-analyst','parent_id':'tool1','content_sha256':'222','metadata':{}},
    ]
    with (root/'11_agent_trace'/'trace.jsonl').open('w') as f:
        for e in trace:f.write(json.dumps(e)+'\n')
    (root/'11_agent_trace'/'open_consequences.json').write_text(json.dumps({
        'total_consequences':1,'open_count':1,'open_consequences':[trace[-1]]
    }))
    (root/'13_timeline').mkdir()
    events=[
        {'timestamp_utc':'2026-08-23T19:59:58Z','source':'runtime','event_type':'file_open','summary':'/tmp/refusal_direction.pt'},
        {'timestamp_utc':'2026-08-23T20:00:00Z','source':'live','event_type':'activation_attestation','summary':'first divergence depth 36'},
        {'timestamp_utc':'2026-08-23T20:00:03Z','source':'agent','event_type':'consequence','summary':'account_disabled'},
    ]
    (root/'13_timeline'/'timeline.json').write_text(json.dumps({'event_count':len(events),'events':events,
        'correlated_change_event':events[0]}))
    # Captured v0.5 fleet state.
    fdb=root/'fleet.db'
    c=sqlite3.connect(fdb)
    c.executescript('''
    CREATE TABLE node_state(node_id TEXT PRIMARY KEY,last_seq INTEGER,last_payload_sha256 TEXT,last_seen_utc TEXT,state TEXT,recovery_streak INTEGER,findings_json TEXT);
    CREATE TABLE alerts(id INTEGER PRIMARY KEY,node_id TEXT,seq INTEGER,created_utc TEXT,severity TEXT,code TEXT,finding_json TEXT);
    ''')
    c.execute('INSERT INTO node_state VALUES(?,?,?,?,?,?,?)',('qwen-prod-01',4382,'abc','2026-08-23T20:00:04Z','CRITICAL',0,json.dumps([{'code':'UNEXPECTED_RUNTIME_HOOK'}])))
    c.execute('INSERT INTO alerts VALUES(?,?,?,?,?,?,?)',(1,'qwen-prod-01',4382,'2026-08-23T20:00:04Z','critical','UNEXPECTED_RUNTIME_HOOK',json.dumps({'code':'UNEXPECTED_RUNTIME_HOOK'})))
    c.commit();c.close()
    (root/'containment.json').write_text(json.dumps({'payload':{'schema':'ai-dfir/containment-control/v0.6','mode':'freeze-tools','incident_id':'CASE-V07'}}))
    (root/'EXECUTION_RESULT.json').write_text(json.dumps({'status':'CONTAINED','mode':'freeze-tools','containment_applied':True}))
    prev='0'*64;a=[]
    for i,(typ,ts) in enumerate([('plan_verified','2026-08-23T20:00:05Z'),('pre_preservation_complete','2026-08-23T20:00:06Z'),('containment_control_applied','2026-08-23T20:00:07Z')]):
        e,prev=audit_event(prev,typ,ts,{'n':i});a.append(e)
    with (root/'containment_audit.jsonl').open('w') as f:
        for e in a:f.write(json.dumps(e,sort_keys=True)+'\n')


def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);args=ap.parse_args()
    out=Path(args.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    case=out/'cases'/'CASE-V07';build_case(case)
    components={}

    # Signed annotation overlay.
    priv=out/'analyst.pem';pub=out/'analyst.pub.pem';generate_key(priv,pub)
    ann=case/'annotations.jsonl'
    add_annotation(ann,priv,'CASE-V07','examiner@example','Runtime hook aligns with first activation divergence.',
                   '01_runtime/runtime_findings.json',['mechanistic-correlation'])
    assert verify_annotations(ann,pub)['valid']
    components['signed_annotations']='PASS'

    # Normalizer.
    model=full_case(case)
    assert model['summary']['confidence_level']==4
    assert model['summary']['first_divergence_depth']==36
    assert model['summary']['open_consequences']==1
    assert len(model['annotations'])==1
    assert model['fleet']['nodes'][0]['state']=='CRITICAL'
    assert any(x['status']=='PASS' for x in model['integrity'] if x['type']=='containment_audit_chain')
    components['normalized_case_model']='PASS'
    components['fleet_state_view']='PASS'

    # Search.
    hits=search(case,'refusal_direction.pt')
    assert hits and hits[0]['file_sha256']
    components['evidence_search']='PASS'

    # Deterministic report.
    report_dir=out/'report';manifest=generate_report(case,report_dir)
    md=(report_dir/'investigator_report.md').read_text()
    assert 'runtime-only model-behavior intervention' in md
    assert 'Missing evidence remains unknown, not clean.' in md
    assert manifest['markdown_sha256']
    components['investigator_report']='PASS'

    # Dashboard read-only/API tests + evidence contamination test.
    before=sha_tree(case)
    app=App(out/'cases');srv=ThreadingHTTPServer(('127.0.0.1',0),Handler);srv.app=app
    th=threading.Thread(target=srv.serve_forever,daemon=True);th.start()
    base=f'http://127.0.0.1:{srv.server_port}'
    with urllib.request.urlopen(base+'/api/cases',timeout=5) as r:cases=json.loads(r.read())['cases']
    assert len(cases)==1;slug=cases[0]['slug']
    with urllib.request.urlopen(base+'/api/case/'+slug,timeout=5) as r:api=json.loads(r.read())
    assert api['summary']['case_id']=='CASE-V07' and api['authority_graph']['nodes']
    with urllib.request.urlopen(base+'/report/'+slug,timeout=5) as r:html=r.read().decode()
    assert 'AI-DFIR Investigator Report' in html
    with urllib.request.urlopen(base+'/api/search/'+slug+'?q=refusal_direction.pt',timeout=5) as r:sr=json.loads(r.read())
    assert sr['hit_count']>=1
    req=urllib.request.Request(base+'/api/case/'+slug,data=b'{}',method='POST')
    rejected=False
    try:urllib.request.urlopen(req,timeout=5)
    except urllib.error.HTTPError as e:rejected=(e.code==405)
    assert rejected
    srv.shutdown();srv.server_close()
    after=sha_tree(case);assert before==after
    components['read_only_dashboard']='PASS'
    components['dashboard_does_not_modify_evidence']='PASS'

    final={'status':'PASS','components':components,'case_summary':model['summary'],'coverage':model['coverage']}
    (out/'V0.7_SELFTEST.json').write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))

if __name__=='__main__':main()
