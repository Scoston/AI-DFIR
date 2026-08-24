#!/usr/bin/env python3
"""Signed normalized enterprise identity envelope for upstream SAML/OIDC gateways.

AI-DFIR does not reimplement XML Signature/SAML validation. A deployment that
terminates SAML at a hardened identity gateway can normalize the validated
assertion into this narrow signed envelope. Raw identity headers are never
trusted by this module.
"""
from __future__ import annotations
import argparse,hashlib,json,uuid
from datetime import datetime,timezone,timedelta
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope

def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def create(subject,tenant_ids,roles,idp,assertion_file,private_key,out,ttl_minutes=15,groups=None):
    raw=Path(assertion_file).read_bytes() if assertion_file else b''
    payload={'schema':'ai-dfir/trusted-identity-envelope/v1.5','identity_id':'ID-'+uuid.uuid4().hex,'subject':subject,'tenant_ids':sorted(set(tenant_ids)),'roles':sorted(set(roles)),'groups':sorted(set(groups or [])),'idp':idp,'upstream_assertion_sha256':hashlib.sha256(raw).hexdigest() if raw else None,'issued_utc':utc(),'expires_utc':(datetime.now(timezone.utc)+timedelta(minutes=ttl_minutes)).isoformat().replace('+00:00','Z')}
    env=sign_payload(Path(private_key),payload);Path(out).write_text(json.dumps(env,indent=2,sort_keys=True));return env
def verify_obj(envelope,public_key):
    payload=verify_envelope(Path(public_key),envelope);findings=[]
    if datetime.now(timezone.utc)>=datetime.fromisoformat(payload['expires_utc'].replace('Z','+00:00')):findings.append({'type':'trusted_identity_envelope_expired','severity':'critical'})
    if not payload.get('tenant_ids'):findings.append({'type':'trusted_identity_tenant_missing','severity':'critical'})
    return {'schema':'ai-dfir/trusted-identity-validation/v1.5','valid':not findings,'principal':payload,'findings':findings}

def verify(path,public_key):return verify_obj(json.loads(Path(path).read_text()),public_key)
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('create');p.add_argument('--subject',required=True);p.add_argument('--tenant',action='append',required=True);p.add_argument('--role',action='append',required=True);p.add_argument('--group',action='append',default=[]);p.add_argument('--idp',required=True);p.add_argument('--assertion-file');p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('verify');p.add_argument('--envelope',required=True);p.add_argument('--public-key',required=True);p.add_argument('--out')
    a=ap.parse_args();o=create(a.subject,a.tenant,a.role,a.idp,a.assertion_file,a.private_key,a.out,groups=a.group) if a.cmd=='create' else verify(a.envelope,a.public_key);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.cmd=='verify' and a.out else print(s);raise SystemExit(0 if a.cmd=='create' or o['valid'] else 2)
if __name__=='__main__':main()
