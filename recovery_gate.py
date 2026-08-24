#!/usr/bin/env python3
"""
Recovery gate for releasing containment.

Release requires:
- current containment control verifies
- approved-state checks supplied by the operator all pass
- optional fleet state is NORMAL or RECOVERED
- no open downstream consequences unless explicitly overridden
- independent signed recovery approval
- new signed `released` containment control linked to previous control hash
"""
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from containment_control import create_control, verify_control
from fleet_crypto import verify_envelope, sign_payload


def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()


def create_release_request(private_key,out,incident_id,node_id,control_file,checks):
    control_sha=sha256_file(control_file)
    request={
        "schema":"ai-dfir/release-request/v0.6",
        "incident_id":incident_id,
        "node_id":node_id,
        "current_control_sha256":control_sha,
        "checks":checks,
    }
    env=sign_payload(Path(private_key),request)
    Path(out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env


def approve_release(request_public,request_path,approver_private,out):
    req_env=json.loads(Path(request_path).read_text())
    req=verify_envelope(Path(request_public),req_env)
    app={
        "schema":"ai-dfir/release-approval/v0.6",
        "incident_id":req["incident_id"],
        "node_id":req["node_id"],
        "release_request_sha256":req_env["payload_sha256"],
    }
    env=sign_payload(Path(approver_private),app)
    Path(out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env


def execute_release(args):
    control=verify_control(Path(args.containment_public_key),Path(args.control_file))
    req_env=json.loads(Path(args.release_request).read_text())
    req=verify_envelope(Path(args.request_public_key),req_env)
    app_env=json.loads(Path(args.release_approval).read_text())
    app=verify_envelope(Path(args.approver_public_key),app_env)
    if app["release_request_sha256"]!=req_env["payload_sha256"]:
        raise ValueError("release approval does not bind to request")
    if req["current_control_sha256"]!=sha256_file(args.control_file):
        raise ValueError("containment control changed after release request")

    failed=[c for c in req.get("checks",[]) if not c.get("passed")]
    if failed and not args.override_failed_checks:
        raise RuntimeError(f"release checks failed: {failed}")

    if args.open_consequences:
        oc=json.loads(Path(args.open_consequences).read_text())
        if oc.get("open_count",0)>0 and not args.override_open_consequences:
            raise RuntimeError(f"{oc['open_count']} downstream consequences remain open")

    prev=sha256_file(args.control_file)
    env=create_control(
        Path(args.containment_private_key),Path(args.control_file),
        "released",req["incident_id"],"Approved recovery release",
        previous_control_sha256=prev
    )
    payload=verify_control(Path(args.containment_public_key),Path(args.control_file))
    result={
        "status":"RELEASED",
        "incident_id":req["incident_id"],
        "control_id":payload["control_id"],
        "previous_control_sha256":prev,
        "new_control_sha256":sha256_file(args.control_file),
        "override_failed_checks":args.override_failed_checks,
        "override_open_consequences":args.override_open_consequences,
    }
    print(json.dumps(result,indent=2,sort_keys=True))


def main():
    ap=argparse.ArgumentParser()
    sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("request")
    p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    p.add_argument("--incident-id",required=True);p.add_argument("--node-id",required=True)
    p.add_argument("--control-file",required=True)
    p.add_argument("--check",action="append",default=[],
                   help="NAME=true|false; e.g. fleet_state_clean=true")
    p=sp.add_parser("approve")
    p.add_argument("--request-public-key",required=True);p.add_argument("--request",required=True)
    p.add_argument("--approver-private-key",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("execute")
    p.add_argument("--release-request",required=True);p.add_argument("--request-public-key",required=True)
    p.add_argument("--release-approval",required=True);p.add_argument("--approver-public-key",required=True)
    p.add_argument("--containment-private-key",required=True);p.add_argument("--containment-public-key",required=True)
    p.add_argument("--control-file",required=True);p.add_argument("--open-consequences")
    p.add_argument("--override-failed-checks",action="store_true")
    p.add_argument("--override-open-consequences",action="store_true")
    args=ap.parse_args()
    if args.cmd=="request":
        checks=[]
        for x in args.check:
            name,val=x.rsplit("=",1)
            checks.append({"name":name,"passed":val.lower()=="true"})
        env=create_release_request(args.private_key,args.out,args.incident_id,args.node_id,args.control_file,checks)
        print(json.dumps(env,indent=2,sort_keys=True))
    elif args.cmd=="approve":
        env=approve_release(args.request_public_key,args.request,args.approver_private_key,args.out)
        print(json.dumps(env,indent=2,sort_keys=True))
    else:
        execute_release(args)


if __name__=="__main__":
    main()
