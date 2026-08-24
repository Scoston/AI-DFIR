#!/usr/bin/env python3
"""A2A v1.0 Agent Card JWS signing/verification with trust policy."""
from __future__ import annotations
import argparse, base64, hashlib, json
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlparse
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa,padding,ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature,decode_dss_signature

from a2a_jcs import strict_load,strict_loads,prepare_agent_card,canonicalize,b64u,b64u_decode
from a2a_trust_store import load_store,jwk_thumbprint

def now():return datetime.now(timezone.utc)
def parse_time(s):
    if not s:return None
    return datetime.fromisoformat(str(s).replace("Z","+00:00"))
def origin(url):
    try:
        u=urlparse(url)
        if u.scheme and u.hostname:
            port=f":{u.port}" if u.port else ""
            return f"{u.scheme.lower()}://{u.hostname.lower()}{port}"
    except Exception:pass
    return None

def intb64(s):return int.from_bytes(b64u_decode(s),"big")

def public_from_jwk(jwk):
    kty=jwk.get("kty")
    if kty=="RSA":
        return rsa.RSAPublicNumbers(intb64(jwk["e"]),intb64(jwk["n"])).public_key()
    if kty=="EC":
        if jwk.get("crv")!="P-256":raise ValueError("only P-256 supported for ES256")
        return ec.EllipticCurvePublicNumbers(intb64(jwk["x"]),intb64(jwk["y"]),ec.SECP256R1()).public_key()
    if kty=="OKP":
        if jwk.get("crv")!="Ed25519":raise ValueError("only Ed25519 supported for EdDSA")
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    raise ValueError(f"unsupported JWK kty {kty}")

def public_jwk_from_key(pub,kid=None,alg=None):
    if isinstance(pub,rsa.RSAPublicKey):
        n=pub.public_numbers()
        obj={"kty":"RSA","n":b64u(n.n.to_bytes((n.n.bit_length()+7)//8,"big")),
             "e":b64u(n.e.to_bytes((n.e.bit_length()+7)//8,"big"))}
    elif isinstance(pub,ec.EllipticCurvePublicKey):
        n=pub.public_numbers()
        if not isinstance(pub.curve,ec.SECP256R1):raise ValueError("only P-256 supported")
        obj={"kty":"EC","crv":"P-256","x":b64u(n.x.to_bytes(32,"big")),"y":b64u(n.y.to_bytes(32,"big"))}
    elif isinstance(pub,ed25519.Ed25519PublicKey):
        raw=pub.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        obj={"kty":"OKP","crv":"Ed25519","x":b64u(raw)}
    else:raise ValueError("unsupported public key")
    if kid:obj["kid"]=kid
    if alg:obj["alg"]=alg
    return obj

def alg_for_private(priv):
    if isinstance(priv,ec.EllipticCurvePrivateKey):return "ES256"
    if isinstance(priv,rsa.RSAPrivateKey):return "RS256"
    if isinstance(priv,ed25519.Ed25519PrivateKey):return "EdDSA"
    raise ValueError("unsupported private key")

def verify_bytes(pub,alg,signing_input,sig):
    if alg=="ES256":
        if len(sig)!=64:raise ValueError("ES256 JWS signature must be 64-byte r||s")
        der=encode_dss_signature(int.from_bytes(sig[:32],"big"),int.from_bytes(sig[32:],"big"))
        pub.verify(der,signing_input,ec.ECDSA(hashes.SHA256()))
    elif alg=="RS256":
        pub.verify(sig,signing_input,padding.PKCS1v15(),hashes.SHA256())
    elif alg=="PS256":
        pub.verify(sig,signing_input,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    elif alg=="EdDSA":
        pub.verify(sig,signing_input)
    else:raise ValueError(f"unsupported JWS alg {alg}")

def sign_bytes(priv,alg,signing_input):
    if alg=="ES256":
        der=priv.sign(signing_input,ec.ECDSA(hashes.SHA256()))
        r,s=decode_dss_signature(der);return r.to_bytes(32,"big")+s.to_bytes(32,"big")
    if alg=="RS256":return priv.sign(signing_input,padding.PKCS1v15(),hashes.SHA256())
    if alg=="PS256":return priv.sign(signing_input,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    if alg=="EdDSA":return priv.sign(signing_input)
    raise ValueError(alg)

def card_validation(card):
    findings=[]
    required=["name","description","supportedInterfaces","version","capabilities","defaultInputModes","defaultOutputModes","skills"]
    for k in required:
        if k not in card:findings.append({"type":"a2a_required_card_field_missing","severity":"critical","field":k})
    for k in ("supportedInterfaces","defaultInputModes","defaultOutputModes","skills"):
        if k in card and isinstance(card[k],list) and len(card[k])==0:
            findings.append({"type":"a2a_required_array_empty","severity":"high","field":k})
    schemes=set((card.get("securitySchemes") or {}).keys())
    for req in card.get("securityRequirements") or []:
        if isinstance(req,dict):
            for name in req:
                if name not in schemes:findings.append({"type":"a2a_security_requirement_unknown_scheme","severity":"critical","scheme":name})
    for skill in card.get("skills") or []:
        for req in skill.get("securityRequirements") or []:
            if isinstance(req,dict):
                for name in req:
                    if name not in schemes:findings.append({"type":"a2a_skill_security_requirement_unknown_scheme","severity":"critical","skill_id":skill.get("id"),"scheme":name})
    for iface in card.get("supportedInterfaces") or []:
        if iface.get("protocolVersion")!="1.0":
            findings.append({"type":"a2a_interface_protocol_version_not_1_0","severity":"medium","interface":iface})
        u=iface.get("url","")
        if iface.get("protocolBinding") in ("JSONRPC","HTTP+JSON") and u and not u.lower().startswith("https://"):
            findings.append({"type":"a2a_non_https_production_interface","severity":"high","url":u})
    return findings

def key_binding(entry,card,header):
    findings=[];trusted=True
    if entry.get("revoked"):
        trusted=False;findings.append({"type":"a2a_signing_key_revoked","severity":"critical","kid":entry.get("kid"),"reason":entry.get("revocation_reason")})
    t=now();nb=parse_time(entry.get("not_before_utc"));ex=parse_time(entry.get("expires_utc"))
    if nb and t<nb:trusted=False;findings.append({"type":"a2a_signing_key_not_yet_valid","severity":"critical","kid":entry.get("kid")})
    if ex and t>=ex:trusted=False;findings.append({"type":"a2a_signing_key_expired","severity":"critical","kid":entry.get("kid")})
    po=entry.get("provider_org")
    if po and (card.get("provider") or {}).get("organization")!=po:
        trusted=False;findings.append({"type":"a2a_provider_binding_mismatch","severity":"critical","expected":po,"actual":(card.get("provider") or {}).get("organization")})
    pu=entry.get("provider_url")
    if pu and origin((card.get("provider") or {}).get("url"))!=origin(pu):
        trusted=False;findings.append({"type":"a2a_provider_url_binding_mismatch","severity":"critical","expected":pu,"actual":(card.get("provider") or {}).get("url")})
    allowed=set(entry.get("allowed_agent_origins") or [])
    if allowed:
        actual={origin(i.get("url")) for i in card.get("supportedInterfaces") or [] if origin(i.get("url"))}
        bad=sorted(actual-allowed)
        if bad:
            trusted=False;findings.append({"type":"a2a_interface_origin_binding_mismatch","severity":"critical","unapproved_origins":bad})
    jku=header.get("jku")
    if jku and entry.get("source_url") and jku!=entry["source_url"]:
        trusted=False;findings.append({"type":"a2a_jku_trust_source_mismatch","severity":"critical","jku":jku,"trusted_source":entry.get("source_url")})
    return trusted,findings

def verify_card(card,store):
    policy=store.get("policy") or {};findings=card_validation(card)
    signatures=card.get("signatures") or []
    payload_obj=prepare_agent_card(card)
    canonical,engine=canonicalize(payload_obj)
    payload_b64=b64u(canonical)
    keys=store.get("keys") or []
    results=[]
    for idx,sigobj in enumerate(signatures):
        sr={"index":idx,"valid":False,"trusted":False,"findings":[]}
        try:
            protected_raw=b64u_decode(sigobj["protected"])
            protected=strict_loads(protected_raw.decode("utf-8"))
            unprotected=sigobj.get("header") or {}
            overlap=set(protected)&set(unprotected)
            if overlap:raise ValueError(f"protected/unprotected header collision: {sorted(overlap)}")
            header={**unprotected,**protected}
            sr["protected_header"]=protected;sr["header"]=header
            alg=protected.get("alg");kid=protected.get("kid")
            if not alg or not kid:raise ValueError("protected header must include alg and kid")
            if policy.get("require_typ_jose",True) and protected.get("typ")!="JOSE":
                sr["findings"].append({"type":"a2a_jws_typ_not_jose","severity":"high","actual":protected.get("typ")})
            if alg not in policy.get("allowed_algorithms",["ES256","RS256","PS256","EdDSA"]):
                raise ValueError(f"algorithm {alg} disallowed by trust policy")
            if protected.get("b64") is False:
                raise ValueError("A2A Agent Card JWS requires the normal base64url-encoded payload")
            if protected.get("crit"):
                raise ValueError("unsupported critical JWS header parameters")
            if "jku" in unprotected:
                raise ValueError("jku must not be trusted from unprotected header")
            candidates=[e for e in keys if e.get("kid")==kid]
            if not candidates:
                sr["findings"].append({"type":"a2a_signature_key_untrusted","severity":"critical","kid":kid})
                results.append(sr);continue
            signing_input=(sigobj["protected"]+"."+payload_b64).encode("ascii")
            signature=b64u_decode(sigobj["signature"])
            valid_entries=[]
            for e in candidates:
                jwk=e["jwk"]
                if jwk.get("alg") and jwk.get("alg")!=alg:continue
                if jwk.get("use") and jwk.get("use")!="sig":continue
                if jwk.get("key_ops") and "verify" not in jwk.get("key_ops",[]):continue
                try:
                    verify_bytes(public_from_jwk(jwk),alg,signing_input,signature)
                    valid_entries.append(e)
                except Exception:continue
            if not valid_entries:
                sr["findings"].append({"type":"a2a_agent_card_signature_invalid","severity":"critical","kid":kid,"alg":alg})
                results.append(sr);continue
            sr["valid"]=True;sr["kid"]=kid;sr["alg"]=alg
            chosen=valid_entries[0];chosen_trusted=False;chosen_findings=[]
            for e in valid_entries:
                tr,bf=key_binding(e,card,header)
                if tr:
                    chosen=e;chosen_trusted=True;chosen_findings=bf;break
                if not chosen_findings:chosen=e;chosen_findings=bf
            sr["jwk_thumbprint"]=jwk_thumbprint(chosen["jwk"])
            sr["findings"]+=chosen_findings;sr["trusted"]=chosen_trusted
            sr["assurance"]=chosen.get("assurance")
        except Exception as e:
            sr["findings"].append({"type":"a2a_signature_verification_error","severity":"critical","error":repr(e)})
        results.append(sr)
    valid=sum(1 for x in results if x["valid"]);trusted=sum(1 for x in results if x["valid"] and x["trusted"])
    if not signatures:findings.append({"type":"a2a_agent_card_unsigned","severity":"critical"})
    if valid<int(policy.get("min_valid_signatures",1)):
        findings.append({"type":"a2a_signature_policy_unsatisfied","severity":"critical","valid_signatures":valid})
    if trusted<int(policy.get("min_trusted_signatures",1)):
        findings.append({"type":"a2a_trust_policy_unsatisfied","severity":"critical","trusted_signatures":trusted})
    for r in results:findings+=r["findings"]
    policy_ok=not any(x.get("severity")=="critical" for x in findings)
    return {
      "schema":"ai-dfir/a2a-agent-card-verification/v1.3",
      "canonicalization_engine":engine,
      "canonical_payload_sha256":hashlib.sha256(canonical).hexdigest(),
      "canonical_payload_length":len(canonical),
      "signature_count":len(signatures),"valid_signature_count":valid,"trusted_signature_count":trusted,
      "cryptographically_valid":valid>0,"trusted":trusted>0,"policy_satisfied":policy_ok,
      "card_identity":{"name":card.get("name"),"provider":card.get("provider"),"version":card.get("version"),
                       "interfaces":card.get("supportedInterfaces"),"skills":[x.get("id") for x in card.get("skills") or []]},
      "signatures":results,"findings":findings,
      "rule":"A valid JWS proves card integrity for a key; trust additionally requires key lifecycle and provider/interface policy binding."
    }

def sign_card(card,private_key,kid,alg=None,jku=None):
    priv=serialization.load_pem_private_key(Path(private_key).read_bytes(),password=None)
    alg=alg or alg_for_private(priv)
    prepared=prepare_agent_card(card);canonical,engine=canonicalize(prepared)
    protected={"alg":alg,"typ":"JOSE","kid":kid}
    if jku:protected["jku"]=jku
    protected_b64=b64u(json.dumps(protected,sort_keys=True,separators=(",",":")).encode())
    signing_input=(protected_b64+"."+b64u(canonical)).encode("ascii")
    sig=b64u(sign_bytes(priv,alg,signing_input))
    out=dict(card);out.setdefault("signatures",[]);out["signatures"].append({"protected":protected_b64,"signature":sig})
    return out,{"algorithm":alg,"kid":kid,"canonicalization_engine":engine,"payload_sha256":hashlib.sha256(canonical).hexdigest()}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("verify");p.add_argument("--card",required=True);p.add_argument("--trust-store",required=True);p.add_argument("--trust-public-key")
    p.add_argument("--allow-unsigned-trust-store",action="store_true");p.add_argument("--out")
    p=sp.add_parser("sign");p.add_argument("--card",required=True);p.add_argument("--private-key",required=True);p.add_argument("--kid",required=True)
    p.add_argument("--alg");p.add_argument("--jku");p.add_argument("--out",required=True)
    a=ap.parse_args()
    if a.cmd=="verify":
        card=strict_load(a.card);store,meta=load_store(a.trust_store,a.trust_public_key,a.allow_unsigned_trust_store)
        obj=verify_card(card,store);obj["trust_store"]=meta
        text=json.dumps(obj,indent=2,sort_keys=True)
        if a.out:Path(a.out).write_text(text)
        else:print(text)
        if not obj["policy_satisfied"]:raise SystemExit(2)
    else:
        card=strict_load(a.card);obj,meta=sign_card(card,a.private_key,a.kid,a.alg,a.jku)
        Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True))
        print(json.dumps(meta,indent=2,sort_keys=True))
if __name__=="__main__":main()
