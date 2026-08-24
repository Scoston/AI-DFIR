#!/usr/bin/env python3
"""
Trusted reverse-proxy authentication context.

This is NOT an OIDC provider or JWT validator. Production deployments should
authenticate users at a reverse proxy / identity-aware gateway. The gateway
can then sign a short-lived AI-DFIR auth context with a shared HMAC secret.

Headers:
  X-AI-DFIR-Auth: base64url(JSON claims)
  X-AI-DFIR-Auth-Sig: hex HMAC-SHA256 over raw base64url value

Claims:
  sub, role, exp, groups, tenant_id
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, time

def b64url(data: bytes):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str):
    return base64.urlsafe_b64decode(s + "="*((4-len(s)%4)%4))

def sign_context(secret: bytes, claims: dict):
    if "exp" not in claims:
        claims={**claims,"exp":int(time.time())+300}
    raw=b64url(json.dumps(claims,sort_keys=True,separators=(",",":")).encode())
    sig=hmac.new(secret,raw.encode(),hashlib.sha256).hexdigest()
    return raw,sig

def verify_context(secret: bytes, raw: str, sig: str):
    expected=hmac.new(secret,raw.encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,sig):
        raise PermissionError("auth context signature invalid")
    claims=json.loads(b64url_decode(raw))
    if int(claims.get("exp",0)) < int(time.time()):
        raise PermissionError("auth context expired")
    if not claims.get("sub") or not claims.get("role"):
        raise PermissionError("auth context missing sub/role")
    return claims

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("sign");p.add_argument("--secret-hex",required=True);p.add_argument("--claims-json",required=True)
    p=sp.add_parser("verify");p.add_argument("--secret-hex",required=True);p.add_argument("--context",required=True);p.add_argument("--signature",required=True)
    a=ap.parse_args();key=bytes.fromhex(a.secret_hex)
    if a.cmd=="sign":
        raw,sig=sign_context(key,json.loads(a.claims_json))
        print(json.dumps({"context":raw,"signature":sig},indent=2))
    else:
        print(json.dumps(verify_context(key,a.context,a.signature),indent=2,sort_keys=True))

if __name__=="__main__":main()
