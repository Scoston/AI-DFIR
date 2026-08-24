#!/usr/bin/env python3
"""Signed containment plans and independent approval envelopes."""
from __future__ import annotations
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def create_plan(private_key, out, incident_id, node_id, alert_id, mode, reason,
                approved_backend=None, read_only_tools=None,
                preservation_failure_action="abort"):
    plan={
        "schema":"ai-dfir/containment-plan/v0.6",
        "plan_id":str(uuid.uuid4()),
        "incident_id":incident_id,
        "node_id":node_id,
        "source_alert_id":alert_id,
        "created_utc":utc_now(),
        "requested_mode":mode,
        "reason":reason,
        "approved_backend":approved_backend,
        "read_only_tools":sorted(set(read_only_tools or [])),
        "transaction_order":[
            "pre_containment_preservation",
            "verify_preservation_seal",
            "apply_signed_containment_control",
            "post_containment_preservation",
        ],
        "preservation_failure_action":preservation_failure_action,
    }
    env=sign_payload(Path(private_key),plan)
    Path(out).parent.mkdir(parents=True,exist_ok=True)
    Path(out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env


def approve(plan_public, plan_path, approver_private, out):
    plan_env=json.loads(Path(plan_path).read_text())
    plan=verify_envelope(Path(plan_public),plan_env)
    approval={
        "schema":"ai-dfir/containment-approval/v0.6",
        "approval_id":str(uuid.uuid4()),
        "approved_utc":utc_now(),
        "plan_id":plan["plan_id"],
        "incident_id":plan["incident_id"],
        "node_id":plan["node_id"],
        "requested_mode":plan["requested_mode"],
        "plan_payload_sha256":plan_env["payload_sha256"],
    }
    env=sign_payload(Path(approver_private),approval)
    Path(out).write_text(json.dumps(env,indent=2,sort_keys=True))
    return env


def verify_approval(plan_public, plan_path, approver_public, approval_path):
    plan_env=json.loads(Path(plan_path).read_text())
    plan=verify_envelope(Path(plan_public),plan_env)
    app_env=json.loads(Path(approval_path).read_text())
    app=verify_envelope(Path(approver_public),app_env)
    if app["plan_id"]!=plan["plan_id"] or app["plan_payload_sha256"]!=plan_env["payload_sha256"]:
        raise ValueError("approval does not bind to this containment plan")
    return plan,app


def main():
    ap=argparse.ArgumentParser()
    sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("create")
    p.add_argument("--private-key",required=True);p.add_argument("--out",required=True)
    p.add_argument("--incident-id",required=True);p.add_argument("--node-id",required=True)
    p.add_argument("--alert-id",required=True);p.add_argument("--mode",required=True)
    p.add_argument("--reason",required=True);p.add_argument("--approved-backend")
    p.add_argument("--read-only-tool",action="append",default=[])
    p.add_argument("--preservation-failure-action",choices=["abort","contain_anyway"],default="abort")
    p=sp.add_parser("approve")
    p.add_argument("--plan-public-key",required=True);p.add_argument("--plan",required=True)
    p.add_argument("--approver-private-key",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("verify")
    p.add_argument("--plan-public-key",required=True);p.add_argument("--plan",required=True)
    p.add_argument("--approver-public-key",required=True);p.add_argument("--approval",required=True)
    args=ap.parse_args()
    if args.cmd=="create":
        env=create_plan(args.private_key,args.out,args.incident_id,args.node_id,args.alert_id,
                        args.mode,args.reason,args.approved_backend,args.read_only_tool,
                        args.preservation_failure_action)
        print(json.dumps(env,indent=2,sort_keys=True))
    elif args.cmd=="approve":
        env=approve(args.plan_public_key,args.plan,args.approver_private_key,args.out)
        print(json.dumps(env,indent=2,sort_keys=True))
    else:
        plan,app=verify_approval(args.plan_public_key,args.plan,args.approver_public_key,args.approval)
        print(json.dumps({"valid":True,"plan":plan,"approval":app},indent=2,sort_keys=True))


if __name__=="__main__":
    main()
