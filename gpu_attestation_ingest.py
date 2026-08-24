#!/usr/bin/env python3
"""
Ingest NVIDIA/other hardware attestation evidence into an AI-DFIR case.

This tool does NOT pretend that decoding a JWT verifies its signature.
It preserves the raw token hash and extracts claims for correlation.
Use the vendor-supported verifier/NRAS/NVAT workflow to obtain a verified result,
then attach that verifier output with --verifier-output.
"""
import argparse, base64, hashlib, json, time
from pathlib import Path


def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()


def b64url_decode(s):
    s += "="*((4-len(s)%4)%4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token):
    parts=token.strip().split(".")
    if len(parts)!=3: return None
    return {
        "header":json.loads(b64url_decode(parts[0])),
        "claims":json.loads(b64url_decode(parts[1])),
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--token-file",required=True)
    ap.add_argument("--verifier-output",default=None,
                    help="Output from a vendor-supported verifier; preserved and hashed")
    ap.add_argument("--verification-status",choices=["verified","failed","unknown"],default="unknown")
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    p=Path(args.token_file);raw=p.read_text(encoding="utf-8").strip()
    decoded=decode_jwt(raw)
    claims=(decoded or {}).get("claims",{})
    now=int(time.time())
    result={
        "schema":"ai-dfir/hardware-attestation/v0.4",
        "token_sha256":sha256_file(p),
        "token_format":"JWT" if decoded else "unknown",
        "signature_verified_by_this_tool":False,
        "external_verification_status":args.verification_status,
        "issuer":claims.get("iss"),
        "subject":claims.get("sub"),
        "jti":claims.get("jti"),
        "issued_at":claims.get("iat"),
        "expires":claims.get("exp"),
        "not_before":claims.get("nbf"),
        "nonce":claims.get("eat_nonce"),
        "overall_attestation_result":claims.get("x-nvidia-overall-att-result"),
        "expired_at_ingest": bool(claims.get("exp") and claims["exp"] < now),
        "claims":claims,
    }
    if args.verifier_output:
        vp=Path(args.verifier_output)
        result["verifier_output"]={"path":str(vp.resolve()),"sha256":sha256_file(vp)}
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True))
    print(json.dumps({
        "out":str(out),
        "token_sha256":result["token_sha256"],
        "external_verification_status":result["external_verification_status"],
        "overall_attestation_result":result["overall_attestation_result"],
    },indent=2))

if __name__=="__main__":main()
