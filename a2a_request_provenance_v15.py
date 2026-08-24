#!/usr/bin/env python3
"""Signed forensic provenance envelope for an observed A2A request/response pair.

This is an AI-DFIR evidence envelope, not a new A2A wire-protocol signature.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def shab(b):return hashlib.sha256(b).hexdigest()
def create(request_file,response_file,metadata,private_key,out):
    req=Path(request_file).read_bytes();res=Path(response_file).read_bytes()
    payload={'schema':'ai-dfir/a2a-request-provenance/v1.5','request_sha256':shab(req),'response_sha256':shab(res),
             'request_size':len(req),'response_size':len(res),'task_id':metadata.get('task_id'),'context_id':metadata.get('context_id'),
             'tenant_id':metadata.get('tenant_id'),'agent_card_sha256':metadata.get('agent_card_sha256'),'oauth_jti':metadata.get('oauth_jti'),
             'oauth_issuer':metadata.get('oauth_issuer'),'oauth_audience':metadata.get('oauth_audience'),'mtls_spiffe_id':metadata.get('mtls_spiffe_id'),
             'transport_request_id':metadata.get('transport_request_id'),'source_peer':metadata.get('source_peer'),'observed_utc':metadata.get('observed_utc')}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def verify(path,public_key):return verify_envelope(Path(public_key),json.loads(Path(path).read_text()))
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--request',required=True);p.add_argument('--response',required=True);p.add_argument('--metadata-json',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('verify');p.add_argument('--envelope',required=True);p.add_argument('--public-key',required=True)
    a=ap.parse_args();obj=create(a.request,a.response,json.loads(Path(a.metadata_json).read_text()),a.private_key,a.out) if a.cmd=='create' else verify(a.envelope,a.public_key);print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=='__main__':main()
