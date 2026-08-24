#!/usr/bin/env python3
"""Offline-first A2A Agent Card trust-store manager."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, uuid
from datetime import datetime,timezone
from pathlib import Path
from fleet_crypto import sign_payload,verify_envelope
from a2a_jcs import strict_load

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def b64u_dec(s):return base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))

def jwk_thumbprint(jwk):
    kty=jwk.get("kty")
    if kty=="RSA":obj={"e":jwk["e"],"kty":"RSA","n":jwk["n"]}
    elif kty=="EC":obj={"crv":jwk["crv"],"kty":"EC","x":jwk["x"],"y":jwk["y"]}
    elif kty=="OKP":obj={"crv":jwk["crv"],"kty":"OKP","x":jwk["x"]}
    else:raise ValueError(f"unsupported JWK kty {kty}")
    body=json.dumps(obj,sort_keys=True,separators=(",",":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()

def init_store():
    return {
      "schema":"ai-dfir/a2a-trust-store/v1.3",
      "created_utc":utc(),
      "policy":{
        "allowed_algorithms":["ES256","RS256","PS256","EdDSA"],
        "min_valid_signatures":1,
        "min_trusted_signatures":1,
        "require_typ_jose":True,
        "require_provider_binding":True,
        "require_interface_origin_binding":True,
        "allow_remote_jku_fetch":False,
        "allow_embedded_jwk_without_pin":False
      },
      "keys":[]
    }

def load_store(path,public_key=None,allow_unsigned=False):
    obj=json.loads(Path(path).read_text())
    if "payload" in obj and "signature" in obj:
        if not public_key:raise ValueError("signed trust store requires --trust-public-key")
        payload=verify_envelope(Path(public_key),obj)
        return payload,{"signed":True,"verified":True}
    if not allow_unsigned:raise ValueError("unsigned trust store rejected; use signed store or explicit --allow-unsigned-trust-store")
    return obj,{"signed":False,"verified":False}

def import_jwks(store,jwks,source_url=None,provider_org=None,provider_url=None,
                allowed_origins=None,assurance="PINNED",not_before=None,expires=None):
    for jwk in jwks.get("keys",[]):
        kid=jwk.get("kid")
        if not kid:raise ValueError("all imported JWKs require kid")
        entry={
          "entry_id":"KEY-"+uuid.uuid4().hex,
          "kid":kid,"jwk":jwk,"jwk_thumbprint":jwk_thumbprint(jwk),
          "source_url":source_url,"provider_org":provider_org,"provider_url":provider_url,
          "allowed_agent_origins":sorted(set(allowed_origins or [])),
          "assurance":assurance,"not_before_utc":not_before,"expires_utc":expires,
          "revoked":False,"revoked_utc":None,"revocation_reason":None,
          "added_utc":utc(),
        }
        store["keys"].append(entry)
    return store

def sign_store(store,private_key,out):
    env=sign_payload(Path(private_key),store)
    Path(out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("init");p.add_argument("--out",required=True)
    p=sp.add_parser("import-jwks");p.add_argument("--store",required=True);p.add_argument("--jwks",required=True);p.add_argument("--out",required=True)
    p.add_argument("--source-url");p.add_argument("--provider-org");p.add_argument("--provider-url");p.add_argument("--allowed-origin",action="append",default=[])
    p.add_argument("--assurance",default="PINNED");p.add_argument("--not-before");p.add_argument("--expires")
    p=sp.add_parser("revoke");p.add_argument("--store",required=True);p.add_argument("--kid",required=True);p.add_argument("--reason",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("sign");p.add_argument("--store",required=True);p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    a=ap.parse_args()
    if a.cmd=="init":
        obj=init_store();Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True))
    elif a.cmd=="import-jwks":
        store=json.loads(Path(a.store).read_text());jwks=strict_load(a.jwks)
        obj=import_jwks(store,jwks,a.source_url,a.provider_org,a.provider_url,a.allowed_origin,a.assurance,a.not_before,a.expires)
        Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True))
    elif a.cmd=="revoke":
        obj=json.loads(Path(a.store).read_text());hit=False
        for e in obj.get("keys",[]):
            if e.get("kid")==a.kid:
                e["revoked"]=True;e["revoked_utc"]=utc();e["revocation_reason"]=a.reason;hit=True
        if not hit:raise SystemExit("kid not found")
        Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True))
    else:
        obj=sign_store(json.loads(Path(a.store).read_text()),a.private_key,a.out)
    print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=="__main__":main()
