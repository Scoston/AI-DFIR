#!/usr/bin/env python3
"""Envelope encryption contracts for AI-DFIR v1.5 evidence objects.

Provides a local test KEK and an AWS KMS adapter. Azure Key Vault and Google
Cloud KMS adapters are loaded when their official SDKs are installed. Plaintext
DEKs are never serialized into the evidence envelope.
"""
from __future__ import annotations
import argparse,base64,json,os,struct,hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC=b'AIDFIR15E1\n';CHUNK=4*1024*1024

def b64(b):return base64.b64encode(b).decode()
def unb(s):return base64.b64decode(s)
class LocalKEK:
    provider='local-test'
    def __init__(self,key):
        if len(key)!=32:raise ValueError('local KEK must be 32 bytes')
        self.key=key;self.key_id='local:'+hashlib.sha256(key).hexdigest()[:16]
    def wrap(self,dek):
        nonce=os.urandom(12);return nonce+AESGCM(self.key).encrypt(nonce,dek,self.key_id.encode())
    def unwrap(self,blob):return AESGCM(self.key).decrypt(blob[:12],blob[12:],self.key_id.encode())
class AWSKMS:
    provider='aws-kms'
    def __init__(self,key_id,region=None):
        import boto3
        self.key_id=key_id;self.client=boto3.client('kms',region_name=region)
    def wrap(self,dek):return self.client.encrypt(KeyId=self.key_id,Plaintext=dek,EncryptionContext={'purpose':'ai-dfir-evidence'})['CiphertextBlob']
    def unwrap(self,blob):return self.client.decrypt(CiphertextBlob=blob,EncryptionContext={'purpose':'ai-dfir-evidence'})['Plaintext']
class AzureKeyVaultKEK:
    provider='azure-key-vault'
    def __init__(self,key_id,credential=None):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient,EncryptionAlgorithm
        except Exception as e:raise RuntimeError('Azure Key Vault adapter requires azure-identity and azure-keyvault-keys') from e
        self.key_id=key_id;self.alg=EncryptionAlgorithm.rsa_oaep_256;self.client=CryptographyClient(key_id,credential or DefaultAzureCredential())
    def wrap(self,dek):return self.client.encrypt(self.alg,dek).ciphertext
    def unwrap(self,blob):return self.client.decrypt(self.alg,blob).plaintext
class GoogleKMSKEK:
    provider='google-cloud-kms'
    def __init__(self,key_id,client=None):
        try:from google.cloud import kms
        except Exception as e:raise RuntimeError('Google KMS adapter requires google-cloud-kms') from e
        self.key_id=key_id;self.client=client or kms.KeyManagementServiceClient()
    def wrap(self,dek):return self.client.encrypt(request={'name':self.key_id,'plaintext':dek,'additional_authenticated_data':b'ai-dfir-evidence'}).ciphertext
    def unwrap(self,blob):return self.client.decrypt(request={'name':self.key_id,'ciphertext':blob,'additional_authenticated_data':b'ai-dfir-evidence'}).plaintext

def file_sha256(path,chunk=8*1024*1024):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(chunk),b''):h.update(b)
    return h.hexdigest()

def encrypt_file(src,dst,kek,metadata=None):
    src=Path(src);dst=Path(dst);dek=os.urandom(32);wrapped=kek.wrap(dek);file_id=file_sha256(src)
    header={'schema':'ai-dfir/encrypted-object/v1.5','kek_provider':kek.provider,'kek_key_id':kek.key_id,'wrapped_dek_b64':b64(wrapped),'chunk_size':CHUNK,'plaintext_sha256':file_id,'metadata':metadata or {}}
    hb=json.dumps(header,sort_keys=True,separators=(',',':')).encode()
    aes=AESGCM(dek)
    with src.open('rb') as fi,dst.open('wb') as fo:
        fo.write(MAGIC);fo.write(struct.pack('>I',len(hb)));fo.write(hb);idx=0
        while True:
            data=fi.read(CHUNK)
            if not data:break
            nonce=os.urandom(12);aad=file_id.encode()+idx.to_bytes(8,'big');ct=aes.encrypt(nonce,data,aad)
            fo.write(struct.pack('>I',len(ct)));fo.write(nonce);fo.write(ct);idx+=1
    dek=b'\x00'*len(dek)
    return header

def decrypt_file(src,dst,kek):
    src=Path(src);dst=Path(dst)
    with src.open('rb') as fi:
        if fi.read(len(MAGIC))!=MAGIC:raise ValueError('not AIDFIR15E1')
        hl=struct.unpack('>I',fi.read(4))[0];h=json.loads(fi.read(hl));dek=kek.unwrap(unb(h['wrapped_dek_b64']));aes=AESGCM(dek);idx=0;sha=hashlib.sha256()
        with dst.open('wb') as fo:
            while True:
                lb=fi.read(4)
                if not lb:break
                ln=struct.unpack('>I',lb)[0];nonce=fi.read(12);ct=fi.read(ln);pt=aes.decrypt(nonce,ct,h['plaintext_sha256'].encode()+idx.to_bytes(8,'big'));fo.write(pt);sha.update(pt);idx+=1
    if sha.hexdigest()!=h['plaintext_sha256']:raise ValueError('plaintext SHA-256 mismatch')
    return h

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    for cmd in ('encrypt','decrypt'):
        p=sp.add_parser(cmd);p.add_argument('--src',required=True);p.add_argument('--dst',required=True);p.add_argument('--local-key-hex',required=True)
    a=ap.parse_args();k=LocalKEK(bytes.fromhex(a.local_key_hex));obj=encrypt_file(a.src,a.dst,k) if a.cmd=='encrypt' else decrypt_file(a.src,a.dst,k);print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=='__main__':main()
