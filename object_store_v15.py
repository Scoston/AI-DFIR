#!/usr/bin/env python3
"""Immutable evidence object-store adapters for AI-DFIR v1.5."""
from __future__ import annotations
import argparse,hashlib,json,os,shutil
from datetime import datetime,timezone,timedelta
from pathlib import Path

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

class LocalImmutableStore:
    def __init__(self,root):self.root=Path(root).resolve();self.root.mkdir(parents=True,exist_ok=True);(self.root/'objects').mkdir(exist_ok=True);(self.root/'meta').mkdir(exist_ok=True)
    def put(self,src,tenant_id,case_id,classification='internal',retention_days=365,legal_hold=False):
        src=Path(src);digest=sha(src);obj=self.root/'objects'/digest[:2]/digest;obj.parent.mkdir(parents=True,exist_ok=True)
        if not obj.exists():
            tmp=obj.with_suffix('.tmp');shutil.copyfile(src,tmp);os.chmod(tmp,0o400);os.replace(tmp,obj)
        elif sha(obj)!=digest:raise IOError('immutable object digest mismatch')
        meta={'schema':'ai-dfir/object-metadata/v1.5','sha256':digest,'size_bytes':src.stat().st_size,'tenant_id':tenant_id,'case_id':case_id,'classification':classification,'created_utc':utc(),'retention_until_utc':(datetime.now(timezone.utc)+timedelta(days=retention_days)).isoformat().replace('+00:00','Z'),'legal_hold':bool(legal_hold),'backend':'local-immutable','object_uri':'file://'+str(obj)}
        mp=self.root/'meta'/(digest+'.json')
        if mp.exists():
            old=json.loads(mp.read_text());
            # Never weaken retention or legal hold.
            if old.get('legal_hold'):meta['legal_hold']=True
            if old.get('retention_until_utc','')>meta['retention_until_utc']:meta['retention_until_utc']=old['retention_until_utc']
        mp.write_text(json.dumps(meta,indent=2,sort_keys=True));os.chmod(mp,0o400)
        return meta
    def get(self,digest,dst):
        p=self.root/'objects'/digest[:2]/digest
        if not p.exists():raise FileNotFoundError(digest)
        if sha(p)!=digest:raise IOError('stored object hash mismatch')
        shutil.copyfile(p,dst);return {'sha256':digest,'verified':True}
    def set_legal_hold(self,digest,on=True):
        mp=self.root/'meta'/(digest+'.json')
        if not mp.exists():raise FileNotFoundError(digest)
        meta=json.loads(mp.read_text());meta['legal_hold']=bool(on);meta['legal_hold_changed_utc']=utc();os.chmod(mp,0o600);mp.write_text(json.dumps(meta,indent=2,sort_keys=True));os.chmod(mp,0o400);return meta
    def verify(self):
        findings=[];count=0
        for p in (self.root/'objects').glob('*/*'):
            if not p.is_file():continue
            count+=1;got=sha(p)
            if got!=p.name:findings.append({'type':'object_hash_mismatch','path':str(p),'actual':got})
        return {'schema':'ai-dfir/object-store-verification/v1.5','valid':not findings,'object_count':count,'findings':findings}

class S3ObjectLockStore:
    """S3/S3-compatible immutable store. Requires bucket Object Lock to be enabled."""
    def __init__(self,bucket,prefix='ai-dfir',region=None,endpoint_url=None,client=None):
        if client is None:
            import boto3;client=boto3.client('s3',region_name=region,endpoint_url=endpoint_url)
        self.client=client;self.bucket=bucket;self.prefix=prefix.strip('/')
    def put(self,src,tenant_id,case_id,classification='internal',retention_days=365,legal_hold=False):
        src=Path(src);digest=sha(src);key=f'{self.prefix}/objects/{digest[:2]}/{digest}'
        retain=datetime.now(timezone.utc)+timedelta(days=retention_days)
        extra={'Metadata':{'sha256':digest,'tenant-id':tenant_id,'case-id':case_id,'classification':classification},'ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':retain,'ChecksumAlgorithm':'SHA256'}
        if legal_hold:extra['ObjectLockLegalHoldStatus']='ON'
        with src.open('rb') as f:self.client.upload_fileobj(f,self.bucket,key,ExtraArgs=extra)
        head=self.client.head_object(Bucket=self.bucket,Key=key)
        if head.get('Metadata',{}).get('sha256')!=digest:raise IOError('S3 metadata SHA mismatch')
        return {'schema':'ai-dfir/object-metadata/v1.5','sha256':digest,'size_bytes':src.stat().st_size,'tenant_id':tenant_id,'case_id':case_id,'classification':classification,'retention_until_utc':retain.isoformat().replace('+00:00','Z'),'legal_hold':legal_hold,'backend':'s3-object-lock','object_uri':f's3://{self.bucket}/{key}','version_id':head.get('VersionId')}
    def get(self,digest,dst):
        key=f'{self.prefix}/objects/{digest[:2]}/{digest}';resp=self.client.get_object(Bucket=self.bucket,Key=key)
        h=hashlib.sha256();out=Path(dst)
        with out.open('wb') as f:
            body=resp['Body']
            for b in iter(lambda:body.read(8*1024*1024),b''):f.write(b);h.update(b)
        if h.hexdigest()!=digest:out.unlink(missing_ok=True);raise IOError('downloaded S3 object hash mismatch')
        return {'sha256':digest,'verified':True,'version_id':resp.get('VersionId')}
    def set_legal_hold(self,digest,on=True,version_id=None):
        key=f'{self.prefix}/objects/{digest[:2]}/{digest}';kw={'Bucket':self.bucket,'Key':key,'LegalHold':{'Status':'ON' if on else 'OFF'}}
        if version_id:kw['VersionId']=version_id
        return self.client.put_object_legal_hold(**kw)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--put');ap.add_argument('--tenant',default='T1');ap.add_argument('--case',default='C1');a=ap.parse_args();s=LocalImmutableStore(a.root)
    print(json.dumps(s.put(a.put,a.tenant,a.case) if a.put else s.verify(),indent=2,sort_keys=True))
if __name__=='__main__':main()
