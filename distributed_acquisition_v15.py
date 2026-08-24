#!/usr/bin/env python3
"""Signed, allowlisted distributed acquisition tasks for AI-DFIR v1.5.

No arbitrary shell/command field exists. Collectors claim tasks by declared type
and execute only implementation-defined read-only collectors.
"""
from __future__ import annotations
import argparse,hashlib,json,uuid
from datetime import datetime,timezone,timedelta
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope
from enterprise_metadata_store import MetadataStore

ALLOWED={
 'microsoft_graph_security','azure_foundry_logs','openai_org','anthropic_compliance','anthropic_usage',
 'aws_bedrock','google_cloud_logging','github_copilot','claude_code_local','cursor_local',
 'otel_export','filesystem_snapshot','container_metadata'
}

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def create_request(tenant_id,case_id,collector_type,params,actor,private_key,out,expires_minutes=60):
    if collector_type not in ALLOWED:raise ValueError('collector_type not allowlisted')
    forbidden={'command','shell','script','exec','argv'}&set(params)
    if forbidden:raise ValueError('arbitrary execution fields forbidden: '+','.join(sorted(forbidden)))
    payload={'schema':'ai-dfir/acquisition-task/v1.5','task_id':'TASK-'+uuid.uuid4().hex,'tenant_id':tenant_id,'case_id':case_id,
             'collector_type':collector_type,'params':params,'requested_by':actor,'created_utc':utc(),
             'expires_utc':(datetime.now(timezone.utc)+timedelta(minutes=expires_minutes)).isoformat().replace('+00:00','Z'),'nonce':uuid.uuid4().hex}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def verify_request(path,public_key):
    payload=verify_envelope(Path(public_key),json.loads(Path(path).read_text()))
    if payload['collector_type'] not in ALLOWED:raise ValueError('collector no longer allowlisted')
    if datetime.now(timezone.utc)>=datetime.fromisoformat(payload['expires_utc'].replace('Z','+00:00')):raise ValueError('task expired')
    if {'command','shell','script','exec','argv'}&set(payload.get('params') or {}):raise ValueError('arbitrary execution field found')
    return payload
def enqueue(store_dsn,task_path,public_key):
    task=verify_request(task_path,public_key);s=MetadataStore(store_dsn)
    s.put_task(task['tenant_id'],task['case_id'],task['collector_type'],task,task_id=task['task_id']);return task
def signed_receipt(task,collector_id,state,artifacts,private_key,out,findings=None):
    if state not in ('COMPLETE','PARTIAL','FAILED'):raise ValueError(state)
    payload={'schema':'ai-dfir/acquisition-receipt/v1.5','task_id':task['task_id'],'tenant_id':task['tenant_id'],'case_id':task['case_id'],
             'collector_id':collector_id,'collector_type':task['collector_type'],'state':state,'completed_utc':utc(),
             'artifacts':artifacts,'findings':findings or [],'task_payload_sha256':hashlib.sha256(json.dumps(task,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env

def verify_receipt(path,public_key,expected_task_id=None):
    payload=verify_envelope(Path(public_key),json.loads(Path(path).read_text()))
    findings=[]
    if payload.get('schema')!='ai-dfir/acquisition-receipt/v1.5':findings.append({'type':'collector_receipt_schema_invalid','severity':'critical'})
    if expected_task_id and payload.get('task_id')!=expected_task_id:findings.append({'type':'collector_receipt_task_mismatch','severity':'critical','expected':expected_task_id,'actual':payload.get('task_id')})
    if payload.get('state') not in ('COMPLETE','PARTIAL','FAILED'):findings.append({'type':'collector_receipt_state_invalid','severity':'critical'})
    return {'schema':'ai-dfir/acquisition-receipt-validation/v1.5','valid':not findings,'payload':payload,'findings':findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--tenant',required=True);p.add_argument('--case',required=True);p.add_argument('--collector-type',required=True);p.add_argument('--params-json',default='{}');p.add_argument('--actor',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('verify');p.add_argument('--task',required=True);p.add_argument('--public-key',required=True)
    p=sp.add_parser('verify-receipt');p.add_argument('--receipt',required=True);p.add_argument('--public-key',required=True);p.add_argument('--task-id')
    a=ap.parse_args()
    if a.cmd=='create':obj=create_request(a.tenant,a.case,a.collector_type,json.loads(a.params_json),a.actor,a.private_key,a.out)
    elif a.cmd=='verify':obj=verify_request(a.task,a.public_key)
    else:obj=verify_receipt(a.receipt,a.public_key,a.task_id)
    print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=='__main__':main()
