#!/usr/bin/env python3
"""Allowlisted distributed collector worker for AI-DFIR v1.5.

The worker claims a typed acquisition task, dispatches only an implementation
registered in this file, emits a signed receipt, and updates the durable task
state. There is no arbitrary command, shell, script, argv, or eval path.
"""
from __future__ import annotations
import argparse,json,traceback
from pathlib import Path
from enterprise_metadata_store import MetadataStore
from provider_collectors_v15 import openai_org,anthropic_compliance,anthropic_usage,microsoft_graph_security,azure_foundry_logs,google_cloud_logs,github_copilot,aws_bedrock,write_artifact
from local_agent_collectors_v15 import collect as local_collect
from safe_local_collectors_v15 import filesystem_snapshot,container_metadata,otel_export
from distributed_acquisition_v15 import signed_receipt

PROVIDER={
 'openai_org':openai_org,
 'anthropic_compliance':anthropic_compliance,
 'anthropic_usage':anthropic_usage,
 'microsoft_graph_security':microsoft_graph_security,
 'azure_foundry_logs':azure_foundry_logs,
 'google_cloud_logging':google_cloud_logs,
 'github_copilot':github_copilot,
 'aws_bedrock':aws_bedrock,
}
IMPLEMENTED=set(PROVIDER)|{'claude_code_local','cursor_local','filesystem_snapshot','container_metadata','otel_export'}

def execute(task,outdir):
    typ=task['collector_type'];params=dict((task.get('request') or {}).get('params') or {})
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    if typ in PROVIDER:
        obj,meta,limitations=PROVIDER[typ](**params)
        out=outdir/(typ+'.json');rec=write_artifact(out,obj,typ,meta,limitations)
        state='COMPLETE' if rec.get('collection_complete') else 'PARTIAL'
        return state,[{'path':str(out),'sha256':rec['sha256'],'size_bytes':rec['size_bytes'],'source':typ}],limitations
    if typ in ('claude_code_local','cursor_local'):
        agent='claude_code' if typ=='claude_code_local' else 'cursor'
        obj=local_collect(params.get('home',str(Path.home())),params.get('project'),outdir/typ,agent)
        manifest=outdir/(typ+'_manifest.json');manifest.write_text(json.dumps(obj,indent=2,sort_keys=True))
        import hashlib
        raw=manifest.read_bytes();art=[{'path':str(manifest),'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),'source':typ}]
        return ('PARTIAL' if obj.get('gaps') else 'COMPLETE'),art,obj.get('gaps') or []
    if typ=='filesystem_snapshot':
        obj=filesystem_snapshot(params['root'],params.get('max_files',10000));manifest=outdir/'filesystem_snapshot.json';manifest.write_text(json.dumps(obj,indent=2,sort_keys=True));import hashlib;raw=manifest.read_bytes();return ('PARTIAL' if obj.get('gaps') else 'COMPLETE'),[{'path':str(manifest),'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),'source':typ}],obj.get('gaps') or []
    if typ=='container_metadata':
        obj=container_metadata();manifest=outdir/'container_metadata.json';manifest.write_text(json.dumps(obj,indent=2,sort_keys=True));import hashlib;raw=manifest.read_bytes();return 'COMPLETE',[{'path':str(manifest),'sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),'source':typ}],[]
    if typ=='otel_export':
        obj=otel_export(params['src'],outdir/'otel_export'+Path(params['src']).suffix);manifest=outdir/'otel_export_manifest.json';manifest.write_text(json.dumps(obj,indent=2,sort_keys=True));return 'COMPLETE',[{'path':obj['captured_path'],'sha256':obj['sha256'],'size_bytes':obj['size_bytes'],'source':typ}],[]
    raise ValueError('collector implementation not registered: '+typ)

def run_once(dsn,tenant,collector_id,capabilities,outdir,private_key,receipt_dir,lease_seconds=300,identity_json=None,allow_unverified_reference=False):
    s=MetadataStore(dsn);reg=s.get_collector(tenant,collector_id)
    if not reg:raise PermissionError('collector is not enrolled')
    if identity_json:
        identity=json.loads(Path(identity_json).read_text())
        if identity.get('schema')!='ai-dfir/spiffe-mtls-identity/v1.5' or identity.get('trusted') is not True:raise PermissionError('collector SPIFFE identity is not trusted')
        expected=(reg.get('metadata') or {}).get('spiffe_id')
        if expected and identity.get('spiffe_id')!=expected:raise PermissionError('collector SPIFFE identity does not match registry')
    elif not allow_unverified_reference:
        raise PermissionError('verified collector workload identity required; reference mode must be explicitly enabled')
    task=s.claim_task(tenant,collector_id,capabilities,lease_seconds)
    if not task:return {'schema':'ai-dfir/collector-worker/v1.5','status':'IDLE','collector_id':collector_id}
    # The signed task payload is stored inside request_json by enqueue().
    request=task['request'];state='FAILED';arts=[];findings=[]
    try:
        state,arts,notes=execute(task,Path(outdir)/task['task_id']);findings=[{'type':'collector_limitation','severity':'informational','detail':x} for x in notes]
    except Exception as e:
        findings=[{'type':'collector_execution_failed','severity':'critical','error':repr(e),'traceback':traceback.format_exc(limit=5)}]
    receipt_path=Path(receipt_dir)/(task['task_id']+'.receipt.json');receipt_path.parent.mkdir(parents=True,exist_ok=True)
    # request may be the signed task payload or a wrapper; normalize for receipt.
    payload=request.get('payload',request) if isinstance(request,dict) else request
    env=signed_receipt(payload,collector_id,state,arts,private_key,receipt_path,findings)
    s.complete_task(tenant,task['task_id'],collector_id,env,state)
    s.audit(tenant,collector_id,'acquisition_task_completed','acquisition_task',task['task_id'],{'state':state,'artifact_count':len(arts)})
    return {'schema':'ai-dfir/collector-worker/v1.5','status':state,'task_id':task['task_id'],'receipt':str(receipt_path),'artifacts':arts,'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dsn',required=True);ap.add_argument('--tenant',required=True);ap.add_argument('--collector-id',required=True)
    ap.add_argument('--capability',action='append',default=[]);ap.add_argument('--outdir',required=True);ap.add_argument('--receipt-dir',required=True);ap.add_argument('--private-key',required=True);ap.add_argument('--lease-seconds',type=int,default=300);ap.add_argument('--identity-json');ap.add_argument('--allow-unverified-reference',action='store_true')
    a=ap.parse_args();caps=a.capability or sorted(IMPLEMENTED);obj=run_once(a.dsn,a.tenant,a.collector_id,caps,a.outdir,a.private_key,a.receipt_dir,a.lease_seconds,a.identity_json,a.allow_unverified_reference);print(json.dumps(obj,indent=2,sort_keys=True));raise SystemExit(2 if obj['status']=='FAILED' else 0)
if __name__=='__main__':main()
