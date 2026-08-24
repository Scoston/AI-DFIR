#!/usr/bin/env python3
"""Atomic protected evidence-ingest path for AI-DFIR v1.5.

plaintext evidence -> streamed SHA-256 -> envelope encryption -> immutable
ciphertext object -> tenant-scoped metadata record. The source file is never
uploaded to the enterprise object store in plaintext by this workflow.
"""
from __future__ import annotations
import argparse,hashlib,json,os,tempfile
from pathlib import Path
from enterprise_metadata_store import MetadataStore
from kms_envelope_v15 import LocalKEK,AWSKMS,AzureKeyVaultKEK,GoogleKMSKEK,encrypt_file,decrypt_file,file_sha256
from object_store_v15 import LocalImmutableStore,S3ObjectLockStore

def build_kek(cfg):
    p=cfg['provider']
    if p=='local-test':return LocalKEK(bytes.fromhex(cfg['key_hex']))
    if p=='aws_kms':return AWSKMS(cfg['key_id'],cfg.get('region'))
    if p=='azure_key_vault':return AzureKeyVaultKEK(cfg['key_id'])
    if p=='google_cloud_kms':return GoogleKMSKEK(cfg['key_id'])
    raise ValueError('unsupported KEK provider '+p)
def build_store(cfg):
    if cfg['backend']=='local-immutable':return LocalImmutableStore(cfg['root'])
    if cfg['backend']=='s3_object_lock':return S3ObjectLockStore(cfg['bucket'],cfg.get('prefix','ai-dfir'),cfg.get('region'),cfg.get('endpoint_url'))
    raise ValueError('unsupported object store '+cfg['backend'])

def ingest(src,tenant,case_id,dsn,kek_cfg,store_cfg,classification='restricted',retention_days=365,legal_hold=False,receipt_sha256=None,media_type=None):
    src=Path(src).resolve();plain_sha=file_sha256(src);meta_store=MetadataStore(dsn)
    if not meta_store.get_case(tenant,case_id):raise KeyError('case not found in tenant metadata store')
    kek=build_kek(kek_cfg);store=build_store(store_cfg)
    with tempfile.TemporaryDirectory(prefix='ai-dfir-v15-ingest-') as td:
        enc=Path(td)/(plain_sha+'.aidfir15e1');header=encrypt_file(src,enc,kek,{'tenant_id':tenant,'case_id':case_id,'classification':classification})
        cipher_sha=file_sha256(enc);obj=store.put(enc,tenant,case_id,classification,retention_days,legal_hold)
    evid=meta_store.put_evidence(tenant,case_id,plain_sha,src.stat().st_size,obj['object_uri'],media_type,classification,receipt_sha256,
        {'encryption_schema':header['schema'],'kek_provider':header['kek_provider'],'kek_key_id':header['kek_key_id'],'ciphertext_sha256':cipher_sha,
         'stored_object_sha256':obj['sha256'],'retention_until_utc':obj.get('retention_until_utc'),'legal_hold':obj.get('legal_hold'),'version_id':obj.get('version_id')})
    meta_store.audit(tenant,'enterprise_evidence_ingest','evidence_ingested','evidence',evid,{'plaintext_sha256':plain_sha,'ciphertext_sha256':cipher_sha,'object_uri':obj['object_uri']})
    return {'schema':'ai-dfir/enterprise-evidence-ingest/v1.5','tenant_id':tenant,'case_id':case_id,'evidence_id':evid,'plaintext_sha256':plain_sha,
            'ciphertext_sha256':cipher_sha,'object':obj,'kek_provider':header['kek_provider'],'kek_key_id':header['kek_key_id'],'plaintext_uploaded_to_object_store':False}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--src',required=True);ap.add_argument('--tenant',required=True);ap.add_argument('--case',required=True);ap.add_argument('--dsn',required=True);ap.add_argument('--kek-json',required=True);ap.add_argument('--store-json',required=True);ap.add_argument('--classification',default='restricted');ap.add_argument('--retention-days',type=int,default=365);ap.add_argument('--legal-hold',action='store_true');ap.add_argument('--receipt-sha256');ap.add_argument('--media-type');ap.add_argument('--out')
    a=ap.parse_args();o=ingest(a.src,a.tenant,a.case,a.dsn,json.loads(Path(a.kek_json).read_text()),json.loads(Path(a.store_json).read_text()),a.classification,a.retention_days,a.legal_hold,a.receipt_sha256,a.media_type);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
