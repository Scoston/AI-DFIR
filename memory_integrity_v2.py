#!/usr/bin/env python3
"""Signed/versioned persistent-agent memory integrity and retrieval lineage."""
from __future__ import annotations
import argparse,hashlib,json
from datetime import datetime
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def dt(s):return datetime.fromisoformat(str(s).replace('Z','+00:00')) if s else None

def snapshot(records):
    items=[]
    for r in sorted(records,key=lambda x:(str(x.get('tenant_id')),str(x.get('memory_id')))):
        items.append({'memory_id':r.get('memory_id'),'tenant_id':r.get('tenant_id'),'version':r.get('version'),'content_sha256':r.get('content_sha256'),'source_event_id':r.get('source_event_id'),'source_chunk_sha256':r.get('source_chunk_sha256'),'writer_id':r.get('writer_id'),'embedding_model':r.get('embedding_model'),'embedding_version':r.get('embedding_version'),'vector_id':r.get('vector_id'),'created_utc':r.get('created_utc'),'expires_utc':r.get('expires_utc'),'tombstoned_utc':r.get('tombstoned_utc')})
    body=json.dumps(items,sort_keys=True,separators=(',',':')).encode()
    return {'schema':'ai-dfir/memory-snapshot/v1.4','record_count':len(items),'records':items,'snapshot_sha256':hashlib.sha256(body).hexdigest()}

def analyze(events,baseline=None,trusted_writers=None):
    trusted=set(trusted_writers or []);findings=[];state={};history=[]
    base={(r.get('tenant_id'),r.get('memory_id')):r for r in (baseline or {}).get('records',[])}
    for e in sorted(events,key=lambda x:x.get('timestamp_utc') or ''):
        et=e.get('event_type');m=e.get('metadata') or {};mid=m.get('memory_id') or e.get('memory_id') or e.get('target_id');tenant=e.get('tenant_id') or m.get('tenant_id')
        if not mid:continue
        key=(tenant,mid);ts=dt(e.get('timestamp_utc'));version=m.get('version') or e.get('version');content=e.get('content_sha256') or m.get('content_sha256')
        if et in ('memory_write','memory_update','memory_upsert','memory_create'):
            prev=state.get(key) or base.get(key)
            if prev and version is not None and prev.get('version') is not None and int(version)<=int(prev.get('version')):
                findings.append({'type':'memory_version_regression_or_replay','severity':'critical','tenant_id':tenant,'memory_id':mid,'previous_version':prev.get('version'),'observed_version':version,'event_id':e.get('event_id')})
            if trusted and e.get('actor_id') not in trusted:findings.append({'type':'memory_untrusted_writer','severity':'critical','memory_id':mid,'writer':e.get('actor_id'),'event_id':e.get('event_id')})
            if not (m.get('source_event_id') or e.get('cause_event_ids') or m.get('source_chunk_sha256')):findings.append({'type':'memory_missing_source_provenance','severity':'high','memory_id':mid,'event_id':e.get('event_id')})
            if prev and prev.get('tenant_id') not in (None,tenant):findings.append({'type':'memory_cross_tenant_overwrite','severity':'critical','memory_id':mid,'previous_tenant':prev.get('tenant_id'),'tenant_id':tenant})
            rec={'memory_id':mid,'tenant_id':tenant,'version':version,'content_sha256':content,'source_event_id':m.get('source_event_id'),'source_chunk_sha256':m.get('source_chunk_sha256'),'writer_id':e.get('actor_id'),'embedding_model':m.get('embedding_model'),'embedding_version':m.get('embedding_version'),'vector_id':m.get('vector_id'),'created_utc':e.get('timestamp_utc'),'expires_utc':m.get('expires_utc'),'tombstoned_utc':None}
            state[key]=rec;history.append({'operation':'write','event_id':e.get('event_id'),**rec})
        elif et in ('memory_delete','memory_tombstone'):
            rec=state.get(key) or base.get(key) or {'memory_id':mid,'tenant_id':tenant}
            rec=dict(rec);rec['tombstoned_utc']=e.get('timestamp_utc');state[key]=rec;history.append({'operation':'tombstone','event_id':e.get('event_id'),**rec})
        elif et in ('memory_read','search_memory','retrieval'):
            rec=state.get(key) or base.get(key)
            if not rec:
                candidates=[v for (t,memory_id),v in {**base,**state}.items() if memory_id==mid]
                if candidates:
                    rec=candidates[-1]
                    findings.append({'type':'memory_cross_tenant_read','severity':'critical','memory_id':mid,'record_tenant':rec.get('tenant_id'),'reader_tenant':tenant})
                else:
                    findings.append({'type':'memory_read_without_version_evidence','severity':'high','memory_id':mid,'event_id':e.get('event_id')});continue
            ex=dt(rec.get('expires_utc'));tomb=dt(rec.get('tombstoned_utc'))
            if ts and ex and ts>=ex:findings.append({'type':'memory_read_after_expiry','severity':'critical','memory_id':mid,'event_id':e.get('event_id')})
            if ts and tomb and ts>=tomb:findings.append({'type':'memory_read_after_tombstone','severity':'critical','memory_id':mid,'event_id':e.get('event_id')})
            if tenant!=rec.get('tenant_id') and not any(x.get('type')=='memory_cross_tenant_read' and x.get('event_id')==e.get('event_id') for x in findings):findings.append({'type':'memory_cross_tenant_read','severity':'critical','memory_id':mid,'record_tenant':rec.get('tenant_id'),'reader_tenant':tenant,'event_id':e.get('event_id')})
            expected=m.get('expected_content_sha256')
            if expected and expected!=rec.get('content_sha256'):findings.append({'type':'memory_read_content_hash_mismatch','severity':'critical','memory_id':mid,'expected':expected,'actual':rec.get('content_sha256')})
            if m.get('embedding_model') and rec.get('embedding_model') and m.get('embedding_model')!=rec.get('embedding_model'):findings.append({'type':'memory_embedding_model_drift','severity':'high','memory_id':mid,'stored':rec.get('embedding_model'),'read':m.get('embedding_model')})
            history.append({'operation':'read','event_id':e.get('event_id'),'memory_id':mid,'tenant_id':tenant,'version':rec.get('version'),'content_sha256':rec.get('content_sha256')})
    snap=snapshot(list(state.values()) if state else list(base.values()))
    return {'schema':'ai-dfir/memory-integrity/v1.4','snapshot':snap,'history':history,'findings':findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('snapshot');p.add_argument('--records',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('verify-snapshot');p.add_argument('--snapshot',required=True);p.add_argument('--public-key',required=True)
    p=sp.add_parser('analyze');p.add_argument('--events',required=True);p.add_argument('--baseline');p.add_argument('--trusted-writer',action='append',default=[]);p.add_argument('--out')
    a=ap.parse_args()
    if a.cmd=='snapshot':
        r=json.loads(Path(a.records).read_text());r=r.get('records',r);env=sign_payload(Path(a.private_key),snapshot(r));Path(a.out).write_text(json.dumps(env,indent=2,sort_keys=True));print(json.dumps(env,indent=2,sort_keys=True));return
    if a.cmd=='verify-snapshot':
        p=verify_envelope(Path(a.public_key),json.loads(Path(a.snapshot).read_text()));print(json.dumps({'valid':True,'payload':p},indent=2,sort_keys=True));return
    ev=json.loads(Path(a.events).read_text());ev=ev.get('events',ev);base=None
    if a.baseline:
        obj=json.loads(Path(a.baseline).read_text());base=obj.get('payload',obj)
    o=analyze(ev,base,a.trusted_writer);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
