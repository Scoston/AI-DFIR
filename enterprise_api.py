#!/usr/bin/env python3
"""
Enterprise case-management API.

Authentication boundary:
- Production: place behind an OIDC/SAML-capable reverse proxy or identity-aware gateway.
- The gateway signs short-lived auth claims using trusted_auth_context.py.
- This service does NOT implement an identity provider.

Binary evidence download/upload is deliberately excluded from this API in v1.0.
Evidence moves through verified collector bundles / repository materialization.
"""
from __future__ import annotations
import argparse, json, os, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from pathlib import Path
from enterprise_case import CaseDB
from evidence_repository import Repository
from enterprise_rbac import require, can_read_classification
from trusted_auth_context import verify_context

class App:
    def __init__(self,cases_db,repo_root,auth_secret,repo_key=None):
        self.cases=CaseDB(cases_db);self.repo=Repository(repo_root,repo_key);self.auth_secret=auth_secret
    def auth(self,headers):
        raw=headers.get("X-AI-DFIR-Auth");sig=headers.get("X-AI-DFIR-Auth-Sig")
        if not raw or not sig:raise PermissionError("missing trusted auth context")
        return verify_context(self.auth_secret,raw,sig)
    def tenant_case(self,claims,cid):
        case=self.cases.get(cid)
        if not case:raise KeyError(cid)
        if claims.get("role")!="admin":
            ct=case.get("tenant_id");ut=claims.get("tenant_id")
            if ct and ct!=ut:raise PermissionError("cross-tenant access denied")
        return case

class Handler(BaseHTTPRequestHandler):
    server_version="AI-DFIR-Enterprise/1.0"
    def sendj(self,status,obj):
        b=json.dumps(obj,sort_keys=True,default=str).encode()
        self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
    def claims(self):
        return self.server.app.auth(self.headers)
    def body(self):
        n=int(self.headers.get("Content-Length","0"));return json.loads(self.rfile.read(n) or b"{}")
    def do_GET(self):
        try:
            u=urlparse(self.path)
            if u.path=="/healthz":return self.sendj(200,{"status":"ok","version":"1.0"})
            c=self.claims();role=c["role"]
            if u.path=="/v1/cases":
                require(role,"case.read")
                rows=self.server.app.cases.list(c.get("tenant_id") if role!="admin" else None)
                return self.sendj(200,{"cases":rows})
            m=re.fullmatch(r"/v1/cases/([^/]+)",u.path)
            if m:
                require(role,"case.read");case=self.server.app.tenant_case(c,m.group(1));return self.sendj(200,case)
            m=re.fullmatch(r"/v1/cases/([^/]+)/evidence",u.path)
            if m:
                require(role,"evidence.metadata.read");self.server.app.tenant_case(c,m.group(1))
                rows=[x for x in self.server.app.repo.list_case(m.group(1))
                      if can_read_classification(role,x["classification"])]
                return self.sendj(200,{"evidence":rows})
            m=re.fullmatch(r"/v1/cases/([^/]+)/holds",u.path)
            if m:
                require(role,"legal_hold.read");self.server.app.tenant_case(c,m.group(1))
                return self.sendj(200,{"holds":self.server.app.repo.active_holds(m.group(1))})
            return self.sendj(404,{"error":"not found"})
        except PermissionError as e:return self.sendj(403,{"error":str(e)})
        except KeyError as e:return self.sendj(404,{"error":str(e)})
        except Exception as e:return self.sendj(400,{"error":repr(e)})
    def do_POST(self):
        try:
            c=self.claims();role=c["role"];b=self.body();u=urlparse(self.path)
            if u.path=="/v1/cases":
                require(role,"case.create")
                cid=self.server.app.cases.create(
                    b["title"],b.get("severity","medium"),c["sub"],
                    tenant_id=c.get("tenant_id"),owner=b.get("owner"),summary=b.get("summary"),tags=b.get("tags"))
                return self.sendj(201,{"case_id":cid})
            m=re.fullmatch(r"/v1/cases/([^/]+)/transition",u.path)
            if m:
                require(role,"case.transition");self.server.app.tenant_case(c,m.group(1))
                self.server.app.cases.transition(m.group(1),b["status"],c["sub"],b["reason"])
                return self.sendj(200,self.server.app.cases.get(m.group(1)))
            m=re.fullmatch(r"/v1/cases/([^/]+)/assign",u.path)
            if m:
                require(role,"case.assign");self.server.app.tenant_case(c,m.group(1))
                self.server.app.cases.assign(m.group(1),b["user_id"],b.get("member_role","analyst"),c["sub"])
                return self.sendj(200,self.server.app.cases.get(m.group(1)))
            m=re.fullmatch(r"/v1/cases/([^/]+)/holds",u.path)
            if m:
                require(role,"legal_hold.create");self.server.app.tenant_case(c,m.group(1))
                hid=self.server.app.repo.create_hold(m.group(1),b["reason"],c["sub"],b.get("evidence_id"))
                return self.sendj(201,{"hold_id":hid})
            return self.sendj(404,{"error":"not found"})
        except PermissionError as e:return self.sendj(403,{"error":str(e)})
        except KeyError as e:return self.sendj(404,{"error":str(e)})
        except Exception as e:return self.sendj(400,{"error":repr(e)})
    def log_message(self,fmt,*args):
        print("[enterprise-api] "+fmt%args)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--cases-db",required=True);ap.add_argument("--repository",required=True)
    ap.add_argument("--auth-secret-hex",required=True);ap.add_argument("--repository-key-hex")
    ap.add_argument("--host",default="127.0.0.1");ap.add_argument("--port",type=int,default=8890)
    a=ap.parse_args()
    app=App(a.cases_db,a.repository,bytes.fromhex(a.auth_secret_hex),
            bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
    srv=ThreadingHTTPServer((a.host,a.port),Handler);srv.app=app
    print(json.dumps({"listen":f"http://{a.host}:{a.port}","version":"1.0"},indent=2),flush=True)
    srv.serve_forever()
if __name__=="__main__":main()
