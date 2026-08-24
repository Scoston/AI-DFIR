#!/usr/bin/env python3
"""Offline/pinned-JWKS OIDC verifier for AI-DFIR v1.5.

No automatic discovery or remote JWKS retrieval occurs in this verifier.
The deployment must acquire and rotate issuer metadata/JWKS through an approved
configuration process, preventing untrusted tokens from selecting a trust URL.
"""
from __future__ import annotations
import argparse,json,time
from pathlib import Path
import jwt

ALGS=('RS256','PS256','ES256','EdDSA')

def _keys(jwks):
    out={}
    for j in jwks.get('keys',[]):
        kid=j.get('kid')
        if not kid:continue
        try:out[kid]=jwt.PyJWK.from_dict(j).key
        except Exception:continue
    return out

def _epoch(v):
    if v is None:return None
    if isinstance(v,(int,float)):return float(v)
    from datetime import datetime,timezone
    return datetime.fromisoformat(str(v).replace('Z','+00:00')).timestamp()

def verify_token(token,jwks,issuer,audience,tenant_claim='tenant_id',roles_claim='roles',groups_claim='groups',allowed_algs=ALGS,leeway=60,evaluation_time=None):
    """Verify signature/issuer/audience and evaluate temporal claims at time T.

    `evaluation_time` may be epoch seconds or ISO-8601. If omitted, current
    time is used. This is important for incident reconstruction: a token that
    is expired today may still have been valid at the event timestamp.
    """
    import time as _time
    hdr=jwt.get_unverified_header(token);kid=hdr.get('kid');alg=hdr.get('alg')
    findings=[]
    if alg not in allowed_algs:raise ValueError(f'disallowed JWT alg {alg}')
    keys=_keys(jwks)
    if kid not in keys:raise ValueError('JWT kid not present in pinned JWKS')
    claims=jwt.decode(token,keys[kid],algorithms=[alg],issuer=issuer,audience=audience,leeway=leeway,
                      options={'require':['exp','iss','aud','sub'],'verify_exp':False,'verify_nbf':False,'verify_iat':False})
    t=_epoch(evaluation_time) if evaluation_time is not None else _time.time()
    exp=_epoch(claims.get('exp'));nbf=_epoch(claims.get('nbf'));iat=_epoch(claims.get('iat'))
    if exp is not None and t>exp+leeway:findings.append({'type':'oidc_token_expired_at_evaluation_time','severity':'critical','evaluation_time':t,'exp':exp})
    if nbf is not None and t+leeway<nbf:findings.append({'type':'oidc_token_not_yet_valid_at_evaluation_time','severity':'critical','evaluation_time':t,'nbf':nbf})
    if iat is not None and t+leeway<iat:findings.append({'type':'oidc_token_issued_after_evaluation_time','severity':'critical','evaluation_time':t,'iat':iat})
    tenant=claims.get(tenant_claim);roles=claims.get(roles_claim) or [];groups=claims.get(groups_claim) or []
    if isinstance(roles,str):roles=[roles]
    if isinstance(groups,str):groups=[groups]
    tids=claims.get('tenant_ids') or ([tenant] if tenant else [])
    if not tids:findings.append({'type':'oidc_tenant_claim_missing','severity':'critical'})
    return {'schema':'ai-dfir/oidc-principal/v1.5','subject':claims['sub'],'issuer':claims['iss'],'audience':claims['aud'],
            'tenant_id':tenant,'tenant_ids':tids,'roles':sorted(set(roles)),'groups':sorted(set(groups)),
            'issued_at':claims.get('iat'),'not_before':claims.get('nbf'),'expires_at':claims['exp'],'evaluation_time':t,
            'kid':kid,'alg':alg,'claims':claims,'trusted':not any(x['severity']=='critical' for x in findings),'findings':findings,
            'rule':'Token trust is evaluated at the incident/event time, not merely at investigation time.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--token',required=True);ap.add_argument('--jwks',required=True);ap.add_argument('--issuer',required=True);ap.add_argument('--audience',required=True);ap.add_argument('--evaluation-time');ap.add_argument('--out')
    a=ap.parse_args();token=Path(a.token).read_text().strip() if Path(a.token).exists() else a.token
    obj=verify_token(token,json.loads(Path(a.jwks).read_text()),a.issuer,a.audience,evaluation_time=a.evaluation_time);txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
    if not obj['trusted']:raise SystemExit(2)
if __name__=='__main__':main()
