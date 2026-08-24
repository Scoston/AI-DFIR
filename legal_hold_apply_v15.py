#!/usr/bin/env python3
"""Apply/release a signed legal hold to durable metadata and immutable objects."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from urllib.parse import urlparse
from enterprise_metadata_store import MetadataStore
from legal_hold_v15 import validate as validate_hold
from object_store_v15 import LocalImmutableStore,S3ObjectLockStore

def apply(dsn,hold_file,hold_public_key,store_cfg,release_file=None,release_public_key=None):
    v=validate_hold(hold_file,hold_public_key,release_file,release_public_key);findings=[]
    if not v['valid']:return {'schema':'ai-dfir/legal-hold-enforcement/v1.5','valid':False,'state':v.get('state'),'findings':v.get('findings',[])}
    hold_env=json.loads(Path(hold_file).read_text());hold=hold_env['payload'];tenant=hold['tenant_id'];case=hold['case_id'];store=MetadataStore(dsn);items=store.list_evidence(tenant,case);state=v['state']
    cfg=store_cfg
    objstore=LocalImmutableStore(cfg['root']) if cfg['backend']=='local-immutable' else S3ObjectLockStore(cfg['bucket'],cfg.get('prefix','ai-dfir'),cfg.get('region'),cfg.get('endpoint_url'))
    changed=[]
    try:
        if state=='ACTIVE':
            if not any(x['hold_id']==hold['hold_id'] for x in store.active_holds(tenant,case)):
                store.put_legal_hold(tenant,case,hold['hold_id'],hold['reason'],hold['created_by'],{'hold_file_sha256':__import__('hashlib').sha256(Path(hold_file).read_bytes()).hexdigest()})
        for e in items:
            digest=(e.get('metadata') or {}).get('stored_object_sha256')
            if not digest:
                findings.append({'type':'legal_hold_object_digest_missing','severity':'critical','evidence_id':e['evidence_id']});continue
            if isinstance(objstore,LocalImmutableStore):objstore.set_legal_hold(digest,state=='ACTIVE')
            else:objstore.set_legal_hold(digest,state=='ACTIVE',(e.get('metadata') or {}).get('version_id'))
            changed.append({'evidence_id':e['evidence_id'],'object_sha256':digest,'legal_hold':state=='ACTIVE'})
        if state=='RELEASED':
            try:store.release_legal_hold(tenant,hold['hold_id'],(json.loads(Path(release_file).read_text()).get('payload') or {}).get('released_by','unknown'))
            except KeyError:pass
    except Exception as e:findings.append({'type':'legal_hold_storage_apply_failed','severity':'critical','error':repr(e)})
    return {'schema':'ai-dfir/legal-hold-enforcement/v1.5','valid':not any(x['severity']=='critical' for x in findings),'state':state,'tenant_id':tenant,'case_id':case,'hold_id':hold['hold_id'],'objects_changed':changed,'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dsn',required=True);ap.add_argument('--hold',required=True);ap.add_argument('--hold-public-key',required=True);ap.add_argument('--store-json',required=True);ap.add_argument('--release');ap.add_argument('--release-public-key');ap.add_argument('--out')
    a=ap.parse_args();o=apply(a.dsn,a.hold,a.hold_public_key,json.loads(Path(a.store_json).read_text()),a.release,a.release_public_key);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
