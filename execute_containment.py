#!/usr/bin/env python3
"""
Execute a signed containment plan as a preservation-first transaction.

Sequence:
  1 verify plan (+ approval if required)
  2 pre-containment preservation + signed seal
  3 verify seal exists
  4 apply signed containment control atomically
  5 post-containment preservation
  6 record chained audit events

By default, failure to preserve evidence aborts enforcement. Plans can explicitly
choose `contain_anyway` for environments where security containment must take
priority over forensic completeness.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, traceback
from pathlib import Path

from containment_audit import ContainmentAudit
from containment_control import create_control, verify_control
from containment_plan import verify_approval
from fleet_crypto import verify_envelope
from preservation_engine import preserve


def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()


def load_plan(plan_public,plan_path):
    env=json.loads(Path(plan_path).read_text())
    payload=verify_envelope(Path(plan_public),env)
    if payload.get("schema")!="ai-dfir/containment-plan/v0.6":
        raise ValueError("wrong plan schema")
    return env,payload


def execute(args):
    plan_env,plan=load_plan(args.plan_public_key,args.plan)
    incident=plan["incident_id"]
    case_dir=Path(args.case_dir)
    case_dir.mkdir(parents=True,exist_ok=True)

    audit_key=bytes.fromhex(args.audit_hmac_key_hex) if args.audit_hmac_key_hex else None
    audit=ContainmentAudit(case_dir/"containment_audit.jsonl",audit_key)
    audit.add("plan_verified",incident,plan_id=plan["plan_id"],
              plan_sha256=plan_env["payload_sha256"],requested_mode=plan["requested_mode"])

    if args.require_approval:
        if not (args.approver_public_key and args.approval):
            raise ValueError("approval required but approval/public key not supplied")
        _,approval=verify_approval(
            args.plan_public_key,args.plan,args.approver_public_key,args.approval
        )
        audit.add("approval_verified",incident,approval_id=approval["approval_id"])
    elif args.approval and args.approver_public_key:
        _,approval=verify_approval(
            args.plan_public_key,args.plan,args.approver_public_key,args.approval
        )
        audit.add("optional_approval_verified",incident,approval_id=approval["approval_id"])

    pre=None
    preservation_error=None
    try:
        pre=preserve(
            case_dir,incident,"pre",args.copy,args.reference,pid=args.pid,
            signing_key=Path(args.preservation_signing_key) if args.preservation_signing_key else None,
            model_path=args.model_path,
            runtime_collector=not args.skip_runtime_collector
        )
        if args.preservation_signing_key:
            head=Path(pre["phase_dir"])/"signed_seal"/"BUNDLE_HEAD.json"
            if not head.exists():
                raise RuntimeError("pre-containment signed seal missing")
        audit.add("pre_preservation_complete",incident,
                  manifest_sha256=pre["manifest_sha256"],signed=pre["signed"])
    except Exception as e:
        preservation_error=repr(e)
        audit.add("pre_preservation_failed",incident,error=preservation_error,
                  traceback=traceback.format_exc())
        if plan.get("preservation_failure_action","abort")!="contain_anyway":
            result={
                "status":"ABORTED_PRESERVATION_FAILURE",
                "incident_id":incident,
                "error":preservation_error,
                "containment_applied":False,
            }
            (case_dir/"EXECUTION_RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True))
            return result
        audit.add("containment_override_after_preservation_failure",incident)

    previous_hash=None
    control_path=Path(args.control_file)
    if control_path.exists():
        previous_hash=sha256_file(control_path)

    control=create_control(
        Path(args.containment_private_key),control_path,
        plan["requested_mode"],incident,plan["reason"],
        approved_backend=plan.get("approved_backend"),
        read_only_tools=plan.get("read_only_tools"),
        source_alert={"id":plan.get("source_alert_id"),"node_id":plan.get("node_id")},
        previous_control_sha256=previous_hash
    )
    verified=verify_control(Path(args.containment_public_key),control_path)
    audit.add("containment_control_applied",incident,
              mode=verified["mode"],control_id=verified["control_id"],
              control_sha256=sha256_file(control_path))

    post=None
    post_error=None
    try:
        post=preserve(
            case_dir,incident,"post",args.copy,args.reference,pid=args.pid,
            signing_key=Path(args.preservation_signing_key) if args.preservation_signing_key else None,
            model_path=args.model_path,
            runtime_collector=not args.skip_runtime_collector
        )
        audit.add("post_preservation_complete",incident,
                  manifest_sha256=post["manifest_sha256"],signed=post["signed"])
    except Exception as e:
        post_error=repr(e)
        audit.add("post_preservation_failed",incident,error=post_error,
                  traceback=traceback.format_exc())

    result={
        "status":"CONTAINED" if not post_error else "CONTAINED_POST_PRESERVATION_INCOMPLETE",
        "incident_id":incident,
        "plan_id":plan["plan_id"],
        "mode":plan["requested_mode"],
        "containment_applied":True,
        "control_file":str(control_path),
        "control_sha256":sha256_file(control_path),
        "pre_preservation":pre,
        "pre_preservation_error":preservation_error,
        "post_preservation":post,
        "post_preservation_error":post_error,
        "audit_log":str(case_dir/"containment_audit.jsonl"),
        "audit_head":audit.prev,
    }
    (case_dir/"EXECUTION_RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True))
    audit.add("transaction_complete",incident,status=result["status"],
              execution_result_sha256=sha256_file(case_dir/"EXECUTION_RESULT.json"))
    return result


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--plan",required=True)
    ap.add_argument("--plan-public-key",required=True)
    ap.add_argument("--require-approval",action="store_true")
    ap.add_argument("--approval")
    ap.add_argument("--approver-public-key")
    ap.add_argument("--case-dir",required=True)
    ap.add_argument("--containment-private-key",required=True)
    ap.add_argument("--containment-public-key",required=True)
    ap.add_argument("--control-file",required=True)
    ap.add_argument("--preservation-signing-key")
    ap.add_argument("--copy",action="append",default=[])
    ap.add_argument("--reference",action="append",default=[])
    ap.add_argument("--pid",type=int)
    ap.add_argument("--model-path")
    ap.add_argument("--skip-runtime-collector",action="store_true")
    ap.add_argument("--audit-hmac-key-hex")
    args=ap.parse_args()
    result=execute(args)
    print(json.dumps(result,indent=2,sort_keys=True))
    if result["status"].startswith("ABORTED"):
        raise SystemExit(2)


if __name__=="__main__":
    main()
