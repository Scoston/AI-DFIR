#!/usr/bin/env python3
"""Authenticated tenant-scoped read API for durable AI-DFIR metadata.

Authentication modes:
  oidc            Bearer JWT verified against a pinned local JWKS.
  signed_gateway  Signed normalized identity envelope supplied via a file path
                  configured by the trusted local reverse proxy integration.

The API is read-only. Source evidence and case metadata cannot be changed
through this service.
"""
from __future__ import annotations
import argparse,json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from enterprise_metadata_store import MetadataStore
from oidc_identity_v15 import verify_token
from tenant_policy_v15 import require
from trusted_identity_envelope_v15 import verify_obj as verify_identity_envelope_obj

class App:
    def __init__(self,cfg):
        self.cfg=cfg;self.store=MetadataStore(cfg['metadata_dsn']);self.mode=cfg.get('auth_mode','oidc')
        self.jwks=json.loads(Path(cfg['oidc']['jwks_file']).read_text()) if self.mode=='oidc' else None
    def principal(self,headers):
        if self.mode=='oidc':
            auth=headers.get('Authorization','')
            if not auth.startswith('Bearer '):raise PermissionError('bearer token required')
            return verify_token(auth[7:],self.jwks,self.cfg['oidc']['issuer'],self.cfg['oidc']['audience'])
        if self.mode=='signed_gateway':
            import base64
            raw=headers.get('X-AI-DFIR-Identity')
            if not raw:raise PermissionError('signed identity envelope required')
            try:
                pad='='*((4-len(raw)%4)%4);env=json.loads(base64.urlsafe_b64decode(raw+pad))
            except Exception as e:raise PermissionError('invalid signed identity envelope encoding') from e
            v=verify_identity_envelope_obj(env,self.cfg['signed_gateway']['public_key'])
            if not v['valid']:raise PermissionError('identity envelope invalid')
            return v['principal']
        raise PermissionError('unsupported auth mode')

def handler(app):
    class H(BaseHTTPRequestHandler):
        server_version='AI-DFIR-Enterprise-Gateway/1.5'
        def log_message(self,*a):pass
        def sendj(self,code,o):
            b=json.dumps(o,sort_keys=True,default=str).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
        def do_POST(self):self.sendj(405,{'error':'read_only'})
        do_PUT=do_POST;do_DELETE=do_POST;do_PATCH=do_POST
        def do_GET(self):
            path=urlparse(self.path).path
            if path=='/healthz':return self.sendj(200,{'status':'ok','version':'1.5','read_only':True})
            try:p=app.principal(self.headers)
            except Exception as e:return self.sendj(401,{'error':'unauthorized','detail':str(e)})
            if path=='/v1/whoami':return self.sendj(200,{'subject':p.get('subject') or p.get('sub'),'tenant_ids':p.get('tenant_ids'),'roles':p.get('roles')})
            parts=[x for x in path.split('/') if x]
            if len(parts)>=4 and parts[0]=='v1' and parts[1]=='tenants':
                tenant=parts[2]
                try:require(p,tenant,'case:read')
                except Exception as e:return self.sendj(403,{'error':'forbidden','detail':str(e)})
                if len(parts)==5 and parts[3]=='cases':
                    c=app.store.get_case(tenant,parts[4]);return self.sendj(200,c) if c else self.sendj(404,{'error':'case_not_found'})
                if len(parts)==6 and parts[3]=='cases' and parts[5]=='evidence':
                    c=app.store.get_case(tenant,parts[4])
                    if not c:return self.sendj(404,{'error':'case_not_found'})
                    return self.sendj(200,{'case':c,'evidence':app.store.list_evidence(tenant,parts[4])})
            return self.sendj(404,{'error':'not_found'})
    return H

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--bind',default='127.0.0.1');ap.add_argument('--port',type=int,default=8891);a=ap.parse_args();cfg=json.loads(Path(a.config).read_text());srv=ThreadingHTTPServer((a.bind,a.port),handler(App(cfg)));print(f'AI-DFIR enterprise gateway listening on {a.bind}:{a.port}');srv.serve_forever()
if __name__=='__main__':main()
