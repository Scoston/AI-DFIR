#!/usr/bin/env python3
"""Explicit deployment probe for an authenticated HTTPS Workbench/API gateway.

The operator supplies the expected hostname. The probe verifies that an
unauthenticated health request is not accepted as an authenticated session and,
when a bearer token or client certificate is supplied, that the authenticated
request succeeds. Secrets are not included in output.
"""
from __future__ import annotations
import argparse,json,os
from urllib.parse import urlparse
from pathlib import Path
import requests

def probe(url,expected_host,token_env=None,client_cert=None,client_key=None,ca_bundle=True):
    u=urlparse(url);findings=[]
    if u.scheme!='https':findings.append({'type':'gateway_not_https','severity':'critical'})
    if u.hostname!=expected_host:findings.append({'type':'gateway_host_mismatch','severity':'critical','expected':expected_host,'actual':u.hostname})
    anon=None;auth=None
    try:anon=requests.get(url,timeout=10,verify=ca_bundle).status_code
    except Exception as e:findings.append({'type':'gateway_anonymous_probe_error','severity':'high','error':repr(e)})
    if anon is not None and anon==200:findings.append({'type':'gateway_anonymous_access_allowed','severity':'critical','status':anon})
    headers={};token_present=False
    if token_env:
        token=os.environ.get(token_env);token_present=bool(token)
        if not token:findings.append({'type':'gateway_auth_token_missing','severity':'critical','env':token_env})
        else:headers['Authorization']='Bearer '+token
    cert=(client_cert,client_key) if client_cert and client_key else client_cert
    if token_env or client_cert:
        try:auth=requests.get(url,headers=headers,cert=cert,timeout=10,verify=ca_bundle).status_code
        except Exception as e:findings.append({'type':'gateway_authenticated_probe_error','severity':'critical','error':repr(e)})
        if auth is not None and auth!=200:findings.append({'type':'gateway_authenticated_health_failed','severity':'critical','status':auth})
    else:findings.append({'type':'gateway_no_authentication_material_supplied','severity':'critical'})
    return {'schema':'ai-dfir/gateway-auth-probe/v1.5','valid':not any(x['severity']=='critical' for x in findings),'url_origin':f'{u.scheme}://{u.netloc}',
            'anonymous_status':anon,'authenticated_status':auth,'token_present':token_present,'client_certificate_present':bool(client_cert),'findings':findings}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--url',required=True);ap.add_argument('--expected-host',required=True);ap.add_argument('--token-env');ap.add_argument('--client-cert');ap.add_argument('--client-key');ap.add_argument('--ca-bundle',default=True);ap.add_argument('--out')
    a=ap.parse_args();verify=a.ca_bundle if a.ca_bundle is True else a.ca_bundle;o=probe(a.url,a.expected_host,a.token_env,a.client_cert,a.client_key,verify);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
