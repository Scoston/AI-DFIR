#!/usr/bin/env python3
"""Read-only enterprise case portal for repository/case metadata."""
from __future__ import annotations
import argparse,html,json,re
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlparse
from enterprise_case import CaseDB
from evidence_repository import Repository
from trusted_auth_context import verify_context
from enterprise_rbac import require,can_read_classification

CSS="""body{font-family:system-ui;margin:0;background:#11151b;color:#e9eef5}.wrap{max-width:1250px;margin:auto;padding:24px}
.card{background:#1a2029;border:1px solid #303946;border-radius:10px;padding:16px;margin:10px 0}
a{color:#9ecbff}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #303946;padding:8px}
.badge{border:1px solid #4a5565;border-radius:999px;padding:3px 8px;font-size:12px}.muted{color:#9aa7b5}"""
class App:
    def __init__(self,cases_db,repo,secret,key=None):
        self.cases=CaseDB(cases_db);self.repo=Repository(repo,key);self.secret=secret
class H(BaseHTTPRequestHandler):
    def claims(self):
        return verify_context(self.server.app.secret,self.headers.get("X-AI-DFIR-Auth",""),self.headers.get("X-AI-DFIR-Auth-Sig",""))
    def sendhtml(self,s):
        b=s.encode();self.send_response(200);self.send_header("Content-Type","text/html;charset=utf-8");self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self):
        try:
            if self.path=="/healthz":
                b=b'{"status":"ok","version":"1.0"}';self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b);return
            c=self.claims();require(c["role"],"case.read")
            u=urlparse(self.path)
            if u.path=="/":
                rows=self.server.app.cases.list(c.get("tenant_id") if c["role"]!="admin" else None)
                trs="".join(f"<tr><td><a href='/case/{html.escape(x['case_id'])}'>{html.escape(x['case_id'])}</a></td><td>{html.escape(x['title'])}</td><td>{html.escape(x['status'])}</td><td>{html.escape(x['severity'])}</td><td>{html.escape(str(x.get('owner') or ''))}</td></tr>" for x in rows)
                return self.sendhtml(f"<html><style>{CSS}</style><div class='wrap'><h1>AI-DFIR Enterprise <span class='muted'>v1.0</span></h1><div class='card'><table><tr><th>Case</th><th>Title</th><th>Status</th><th>Severity</th><th>Owner</th></tr>{trs}</table></div></div></html>")
            m=re.fullmatch(r"/case/([^/]+)",u.path)
            if m:
                case=self.server.app.cases.get(m.group(1))
                if not case:raise KeyError(m.group(1))
                if c["role"]!="admin" and case.get("tenant_id") and case.get("tenant_id")!=c.get("tenant_id"):raise PermissionError("cross-tenant")
                ev=[x for x in self.server.app.repo.list_case(case["case_id"]) if can_read_classification(c["role"],x["classification"])]
                erows="".join(f"<tr><td>{html.escape(x['logical_name'])}</td><td><code>{x['sha256'][:18]}…</code></td><td>{x['size']}</td><td>{x['classification']}</td><td>{'encrypted' if x['encrypted'] else 'plain'}</td></tr>" for x in ev)
                holds=self.server.app.repo.active_holds(case["case_id"])
                return self.sendhtml(f"<html><style>{CSS}</style><div class='wrap'><a href='/'>← Cases</a><h1>{html.escape(case['case_id'])}</h1><div class='card'><h2>{html.escape(case['title'])}</h2><span class='badge'>{case['status']}</span> <span class='badge'>{case['severity']}</span><p>{html.escape(str(case.get('summary') or ''))}</p><p class='muted'>Owner: {html.escape(str(case.get('owner') or ''))} · Evidence visible: {len(ev)} · Active holds: {len(holds)}</p></div><div class='card'><h2>Evidence Metadata</h2><table><tr><th>Name</th><th>SHA-256</th><th>Bytes</th><th>Class</th><th>At rest</th></tr>{erows}</table></div><div class='card'><p class='muted'>Detailed artifact analysis remains in the read-only Analyst Workbench after authorized case materialization.</p></div></div></html>")
            self.send_error(404)
        except PermissionError as e:self.send_error(403,str(e))
        except Exception as e:self.send_error(400,repr(e))
    def do_POST(self):self.send_error(405)
    def do_PUT(self):self.send_error(405)
    def do_DELETE(self):self.send_error(405)
    def log_message(self,fmt,*args):print("[portal] "+fmt%args)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--cases-db",required=True);ap.add_argument("--repository",required=True);ap.add_argument("--auth-secret-hex",required=True);ap.add_argument("--repository-key-hex");ap.add_argument("--host",default="127.0.0.1");ap.add_argument("--port",type=int,default=8891)
    a=ap.parse_args();app=App(a.cases_db,a.repository,bytes.fromhex(a.auth_secret_hex),bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
    srv=ThreadingHTTPServer((a.host,a.port),H);srv.app=app;print(f"http://{a.host}:{a.port}",flush=True);srv.serve_forever()
if __name__=="__main__":main()
