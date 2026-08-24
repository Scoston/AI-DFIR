#!/usr/bin/env python3
"""Offline X.509-SVID / mTLS identity verifier for AI-DFIR v1.5."""
from __future__ import annotations
import argparse,json
from datetime import datetime,timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed25519,padding
from cryptography.x509.oid import ExtensionOID,ExtendedKeyUsageOID

def _verify_sig(cert,issuer):
    pub=issuer.public_key();sig=cert.signature;data=cert.tbs_certificate_bytes;alg=cert.signature_hash_algorithm
    if isinstance(pub,rsa.RSAPublicKey):pub.verify(sig,data,padding.PKCS1v15(),alg)
    elif isinstance(pub,ec.EllipticCurvePublicKey):pub.verify(sig,data,ec.ECDSA(alg))
    elif isinstance(pub,ed25519.Ed25519PublicKey):pub.verify(sig,data)
    else:raise ValueError('unsupported issuer key')

def _verify_crl_sig(crl,issuer):
    pub=issuer.public_key();sig=crl.signature;data=crl.tbs_certlist_bytes;alg=crl.signature_hash_algorithm
    if isinstance(pub,rsa.RSAPublicKey):pub.verify(sig,data,padding.PKCS1v15(),alg)
    elif isinstance(pub,ec.EllipticCurvePublicKey):pub.verify(sig,data,ec.ECDSA(alg))
    elif isinstance(pub,ed25519.Ed25519PublicKey):pub.verify(sig,data)
    else:raise ValueError('unsupported issuer key')

def verify_svid(leaf_pem,bundle_pems,expected_trust_domain=None,expected_spiffe_id=None,usage='client',evaluation_time=None,crl_pems=None):
    leaf=x509.load_pem_x509_certificate(Path(leaf_pem).read_bytes())
    issuers=[x509.load_pem_x509_certificate(Path(p).read_bytes()) for p in bundle_pems]
    findings=[];now=datetime.fromisoformat(str(evaluation_time).replace('Z','+00:00')) if evaluation_time else datetime.now(timezone.utc)
    nb=leaf.not_valid_before_utc if hasattr(leaf,'not_valid_before_utc') else leaf.not_valid_before.replace(tzinfo=timezone.utc);na=leaf.not_valid_after_utc if hasattr(leaf,'not_valid_after_utc') else leaf.not_valid_after.replace(tzinfo=timezone.utc)
    if now<nb or now>=na:findings.append({'type':'svid_certificate_outside_validity','severity':'critical','not_before':nb.isoformat(),'not_after':na.isoformat()})
    uris=[]
    try:uris=[str(x) for x in leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.UniformResourceIdentifier)]
    except Exception:pass
    spiffe=[u for u in uris if u.startswith('spiffe://')]
    if len(spiffe)!=1:findings.append({'type':'svid_spiffe_uri_count_invalid','severity':'critical','uris':spiffe})
    sid=spiffe[0] if len(spiffe)==1 else None
    if expected_spiffe_id and sid!=expected_spiffe_id:findings.append({'type':'svid_identity_mismatch','severity':'critical','expected':expected_spiffe_id,'actual':sid})
    if expected_trust_domain and sid and not sid.startswith('spiffe://'+expected_trust_domain+'/'):
        findings.append({'type':'svid_trust_domain_mismatch','severity':'critical','expected':expected_trust_domain,'actual':sid})
    try:
        eku=leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        wanted=ExtendedKeyUsageOID.CLIENT_AUTH if usage=='client' else ExtendedKeyUsageOID.SERVER_AUTH
        if wanted not in eku:findings.append({'type':'svid_eku_missing','severity':'critical','usage':usage})
    except x509.ExtensionNotFound:findings.append({'type':'svid_eku_missing','severity':'critical','usage':usage})
    trusted_issuer=None
    for issuer in issuers:
        if leaf.issuer!=issuer.subject:continue
        try:_verify_sig(leaf,issuer);trusted_issuer=issuer;break
        except Exception:continue
    if not trusted_issuer:findings.append({'type':'svid_chain_untrusted','severity':'critical'})
    for crl_path in crl_pems or []:
        try:
            crl=x509.load_pem_x509_crl(Path(crl_path).read_bytes())
            if trusted_issuer and crl.issuer==trusted_issuer.subject:
                _verify_crl_sig(crl,trusted_issuer)
                for revoked in crl:
                    if revoked.serial_number==leaf.serial_number:
                        rdate=revoked.revocation_date_utc if hasattr(revoked,'revocation_date_utc') else revoked.revocation_date.replace(tzinfo=timezone.utc)
                        if rdate<=now:findings.append({'type':'svid_revoked_at_evaluation_time','severity':'critical','revoked_utc':rdate.isoformat().replace('+00:00','Z')})
        except Exception as e:findings.append({'type':'svid_crl_validation_error','severity':'high','crl':str(crl_path),'error':repr(e)})
    return {'schema':'ai-dfir/spiffe-mtls-identity/v1.5','spiffe_id':sid,'serial_number':hex(leaf.serial_number),
            'not_before_utc':nb.isoformat().replace('+00:00','Z'),'not_after_utc':na.isoformat().replace('+00:00','Z'),
            'issuer':leaf.issuer.rfc4514_string(),'evaluation_time_utc':now.isoformat().replace('+00:00','Z'),'trusted':not any(x['severity']=='critical' for x in findings),'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--leaf',required=True);ap.add_argument('--bundle',action='append',required=True);ap.add_argument('--trust-domain');ap.add_argument('--spiffe-id');ap.add_argument('--usage',choices=['client','server'],default='client');ap.add_argument('--evaluation-time');ap.add_argument('--crl',action='append',default=[]);ap.add_argument('--out')
    a=ap.parse_args();obj=verify_svid(a.leaf,a.bundle,a.trust_domain,a.spiffe_id,a.usage,a.evaluation_time,a.crl);txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
    if not obj['trusted']:raise SystemExit(2)
if __name__=='__main__':main()
