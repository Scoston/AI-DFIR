#!/usr/bin/env python3
import json, os, shutil, sqlite3, subprocess, sys, threading, time, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from fleet_crypto import generate
from enterprise_rbac import authorize, can_read_classification
from trusted_auth_context import sign_context, verify_context
from enterprise_case import CaseDB
from evidence_repository import Repository
from collector_bundle import create as create_bundle, verify as verify_bundle
from collector_registry import load as load_collectors, save as save_collectors
from fleet_crypto import load_public, key_id
from content_pack_manager import build as build_content, verify as verify_content
from enterprise_exports import ocsf
from evidence_tasks import TaskDB
from enterprise_api import App as APIApp, Handler as APIHandler
from http.server import ThreadingHTTPServer

def writej(p,o):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True))
def get(url,headers=None):
    req=urllib.request.Request(url,headers=headers or {})
    try:
        with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read()) if e.headers.get("Content-Type","").startswith("application/json") else {"error":e.reason}
def post(url,obj,headers=None):
    h={"Content-Type":"application/json",**(headers or {})}
    req=urllib.request.Request(url,data=json.dumps(obj).encode(),headers=h,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:b=json.loads(e.read())
        except Exception:b={"error":e.reason}
        return e.code,b

def auth_headers(secret,sub,role,tenant):
    raw,sig=sign_context(secret,{"sub":sub,"role":role,"tenant_id":tenant,"exp":int(time.time())+300})
    return {"X-AI-DFIR-Auth":raw,"X-AI-DFIR-Auth-Sig":sig}

def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);a=ap.parse_args()
    out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    results={}

    # 1. RBAC / classification.
    assert authorize("analyst","evidence.ingest")
    assert not authorize("analyst","legal_hold.create")
    assert can_read_classification("analyst","confidential")
    assert not can_read_classification("analyst","restricted")
    assert authorize("evidence_custodian","legal_hold.create")
    results["rbac_and_classification"]="PASS"

    # 2. Trusted auth context detects tampering.
    secret=os.urandom(32)
    raw,sig=sign_context(secret,{"sub":"alice","role":"analyst","tenant_id":"TENANT-A","exp":int(time.time())+60})
    assert verify_context(secret,raw,sig)["sub"]=="alice"
    rejected=False
    try:verify_context(secret,raw+"x",sig)
    except Exception:rejected=True
    assert rejected
    results["trusted_auth_context"]="PASS"

    # 3. Enterprise cases.
    cases_db=out/"cases.db";cases=CaseDB(cases_db)
    cid=cases.create("Synthetic AI Incident","critical","commander",tenant_id="TENANT-A",summary="test")
    cases.transition(cid,"TRIAGE","commander","validated alert")
    cases.transition(cid,"INVESTIGATING","commander","evidence collection")
    cases.assign(cid,"alice","analyst","commander")
    case=cases.get(cid)
    assert case["status"]=="INVESTIGATING" and case["tenant_id"]=="TENANT-A"
    results["case_lifecycle"]="PASS"

    # 4. Encrypted CAS evidence + dedup + legal hold/retention.
    repo_key=os.urandom(32);repo=Repository(out/"repo",repo_key)
    f1=out/"AlertInfo.json";f1.write_text('{"alert":"AI"}')
    e1=repo.add_file(cid,f1,"AlertInfo.json","custodian",source="synthetic",
                     classification="restricted",retention_days=0,metadata={"workspace_path":"AlertInfo.json"})
    e2=repo.add_file(cid,f1,"AlertInfo-copy.json","custodian",source="synthetic",
                     classification="confidential",retention_days=0)
    assert e1["sha256"]==e2["sha256"]
    with repo.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM objects").fetchone()[0]==1
        assert c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]==2
    extracted=out/"extracted.json";repo.extract(e1["evidence_id"],extracted,"alice")
    assert extracted.read_bytes()==f1.read_bytes()
    hold=repo.create_hold(cid,"litigation/incident hold","custodian")
    plan=repo.disposition_plan(datetime.now(timezone.utc)+timedelta(seconds=1))
    assert not plan["eligible_for_review"] and len(plan["blocked_by_hold"])==2
    assert repo.verify()["valid"]
    results["encrypted_cas_legal_hold"]="PASS"

    # 5. Signed repository checkpoint.
    cp_priv=out/"checkpoint.pem";cp_pub=out/"checkpoint.pub.pem";generate(cp_priv,cp_pub)
    cp=subprocess.run([sys.executable,str(HERE/"repository_checkpoint.py"),"create",
                       "--repository",str(out/"repo"),"--repository-key-hex",repo_key.hex(),
                       "--private-key",str(cp_priv),"--out",str(out/"repo_checkpoint.json")],
                      capture_output=True,text=True)
    assert cp.returncode==0,cp.stderr
    cp2=subprocess.run([sys.executable,str(HERE/"repository_checkpoint.py"),"verify",
                        "--checkpoint",str(out/"repo_checkpoint.json"),"--public-key",str(cp_pub)],
                       capture_output=True,text=True)
    assert cp2.returncode==0,cp2.stderr
    results["signed_repository_checkpoint"]="PASS"

    # 6. Distributed collector identity, tenant binding, bundle integrity.
    col_priv=out/"collector.pem";col_pub=out/"collector.pub.pem";generate(col_priv,col_pub)
    registry=out/"collectors.json"
    pub=load_public(col_pub)
    save_collectors(registry,{"schema":"ai-dfir/collector-registry/v1.0","collectors":{
        "collector-1":{"key_id":key_id(pub),"public_key_pem":col_pub.read_text(),
                       "enabled":True,"allowed_tenants":["TENANT-A"]}
    }})
    artifact=out/"tool_call.json";artifact.write_text('{"tool":"lookup"}')
    bundle=out/"bundle"
    create_bundle(bundle,"collector-1",cid,"TENANT-A",col_priv,[f"tool_call.json={artifact}::confidential"])
    payload,findings=verify_bundle(bundle,registry)
    assert not findings and payload["tenant_id"]=="TENANT-A"
    # Wrong-tenant signed bundle is rejected by collector authorization.
    bad=out/"bad_bundle";create_bundle(bad,"collector-1",cid,"TENANT-B",col_priv,[f"x={artifact}"])
    rejected=False
    try:verify_bundle(bad,registry)
    except PermissionError:rejected=True
    assert rejected
    results["signed_collector_tenant_binding"]="PASS"

    # 7. Enterprise ingest verifies case tenant then enters repository.
    cp=subprocess.run([sys.executable,str(HERE/"enterprise_ingest.py"),
                       "--bundle",str(bundle),"--registry",str(registry),
                       "--repository",str(out/"repo"),"--repository-key-hex",repo_key.hex(),
                       "--cases-db",str(cases_db),"--actor","collector-ingest"],
                      capture_output=True,text=True)
    assert cp.returncode==0,(cp.stdout,cp.stderr)
    assert any(x["logical_name"]=="tool_call.json" for x in repo.list_case(cid))
    results["verified_enterprise_ingest"]="PASS"

    # 8. Materialization honors classification.
    workspace=out/"workspace"
    cp=subprocess.run([sys.executable,str(HERE/"materialize_case.py"),
                       "--repository",str(out/"repo"),"--repository-key-hex",repo_key.hex(),
                       "--case-id",cid,"--out",str(workspace),"--actor","alice",
                       "--role","analyst","--cases-db",str(cases_db)],
                      capture_output=True,text=True)
    assert cp.returncode==0,(cp.stdout,cp.stderr)
    # analyst can see confidential but not restricted AlertInfo.
    assert (workspace/"tool_call.json").exists()
    assert not (workspace/"AlertInfo.json").exists()
    assert (workspace/"REPOSITORY_EXPORT_MANIFEST.json").exists()
    results["classification_aware_materialization"]="PASS"

    # 9. Evidence tasking from the Claude pack on sparse workspace.
    taskdb=TaskDB(out/"tasks.db")
    made=taskdb.create_from_pack(cid,"anthropic.claude_code.prompt_injection",workspace)
    tasks=taskdb.list(cid)
    assert made and tasks and any(x["priority"]=="mandatory" for x in tasks)
    results["evidence_request_tasks"]="PASS"

    # 10. Closure gate blocks a case with mandatory evidence gaps.
    writej(workspace/"incident_profile.json",{"schema":"ai-dfir/incident-profile/v0.9","evidence_pack_id":"anthropic.claude_code.prompt_injection"})
    cp=subprocess.run([sys.executable,str(HERE/"closure_gate.py"),"--workspace",str(workspace)],
                      capture_output=True,text=True)
    assert cp.returncode==2, (cp.stdout,cp.stderr)
    gate=json.loads(cp.stdout)
    assert any(x["type"]=="mandatory_evidence_missing" for x in gate["blockers"])
    results["closure_gate_evidence_sufficiency"]="PASS"

    # 11. Signed detection/evidence content release and tamper rejection.
    content_priv=out/"content.pem";content_pub=out/"content.pub.pem";generate(content_priv,content_pub)
    release=out/"content_release";build_content(release,content_priv,"1.0.0")
    manifest,findings=verify_content(release,content_pub);assert not findings
    first=release/manifest["files"][0]["path"];first.write_bytes(first.read_bytes()+b"tamper")
    _,findings=verify_content(release,content_pub);assert findings
    results["signed_detection_content_release"]="PASS"

    # 12. OCSF 1.8 Incident Finding export.
    ev=ocsf(case,2)
    assert ev["class_uid"]==2005 and ev["type_uid"]==200502
    assert ev["metadata"]["version"]=="1.8.0" and "incident" in ev["metadata"]["profiles"]
    results["ocsf_1_8_incident_export"]="PASS"

    # 13. Enterprise API: authentication, RBAC, tenant isolation.
    app=APIApp(cases_db,out/"repo",secret,repo_key)
    srv=ThreadingHTTPServer(("127.0.0.1",0),APIHandler);srv.app=app
    th=threading.Thread(target=srv.serve_forever,daemon=True);th.start()
    base=f"http://127.0.0.1:{srv.server_port}"
    h_analyst=auth_headers(secret,"alice","analyst","TENANT-A")
    h_ic=auth_headers(secret,"commander","incident_commander","TENANT-A")
    h_other=auth_headers(secret,"eve","incident_commander","TENANT-B")
    st,obj=get(base+f"/v1/cases/{cid}",h_analyst);assert st==200
    st,obj=get(base+f"/v1/cases/{cid}",h_other);assert st==403
    st,obj=post(base+f"/v1/cases/{cid}/transition",{"status":"CONTAINED","reason":"test"},h_analyst);assert st==403
    st,obj=post(base+f"/v1/cases/{cid}/transition",{"status":"CONTAINED","reason":"validated containment"},h_ic);assert st==200
    st,obj=get(base+f"/v1/cases/{cid}/evidence",h_analyst);assert st==200
    # restricted object should be filtered from analyst metadata.
    assert all(x["classification"]!="restricted" for x in obj["evidence"])
    srv.shutdown();srv.server_close()
    results["enterprise_api_rbac_tenant_isolation"]="PASS"

    # 14. Portal remains read-only.
    portal=(HERE/"enterprise_portal.py").read_text()
    assert "def do_POST(self):self.send_error(405)" in portal
    results["read_only_enterprise_portal"]="PASS"

    final={"status":"PASS","components":results}
    (out/"V1.0_SELFTEST.json").write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
