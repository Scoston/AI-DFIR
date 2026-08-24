#!/usr/bin/env python3
"""
Fleet alert -> containment plan responder.

Modes:
  dry-run   : record what would happen, no signed plan/control
  approval  : create signed plans, wait for independent approval/execution
  auto      : create plan and execute preservation-first transaction automatically

The responder never infers action severity from free-form model output. It maps
collector finding codes through an explicit operator-owned policy.
"""
from __future__ import annotations
import argparse, json, os, time, urllib.request, uuid, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from containment_plan import create_plan


HERE=Path(__file__).resolve().parent


def utc_now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def get_json(url,ca=None):
    import ssl
    ctx=ssl.create_default_context(cafile=ca) if url.startswith("https://") else None
    with urllib.request.urlopen(url,timeout=15,context=ctx) as r:return json.loads(r.read())


def load_state(path):
    if Path(path).exists():return json.loads(Path(path).read_text())
    return {"handled_alert_ids":[]}


def save_state(path,state):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    tmp=p.with_suffix(".tmp");tmp.write_text(json.dumps(state,indent=2,sort_keys=True));os.replace(tmp,p)


def action_for(alert,policy):
    f=alert.get("finding") or json.loads(alert.get("finding_json","{}"))
    code=f.get("code")
    mapped=policy.get("alert_actions",{}).get(code)
    if mapped:return mapped
    sev=alert.get("severity") or f.get("severity")
    return policy.get("severity_actions",{}).get(sev,policy.get("default_action","observe"))


def incident_id(node_id,alert_id):
    return f"AIIR-{node_id}-{alert_id}"


def process_alert(alert,cfg,state):
    aid=str(alert["id"])
    if aid in set(state["handled_alert_ids"]): return None
    node=alert["node_id"]
    mode=action_for(alert,cfg["policy"])
    if mode=="observe":
        state["handled_alert_ids"].append(aid)
        return {"alert_id":aid,"node_id":node,"action":"observe"}

    inc=incident_id(node,aid)
    root=Path(cfg["case_root"])/inc
    root.mkdir(parents=True,exist_ok=True)
    plan_path=root/"containment_plan.json"
    finding=alert.get("finding") or json.loads(alert.get("finding_json","{}"))
    reason=f"{finding.get('code')}: {finding.get('message')}"

    plan_env=create_plan(
        cfg["plan_private_key"],plan_path,inc,node,aid,mode,reason,
        approved_backend=(cfg.get("approved_backend_by_node") or {}).get(node),
        read_only_tools=cfg.get("read_only_tools",[]),
        preservation_failure_action=cfg.get("preservation_failure_action","abort")
    )
    record={
        "alert_id":aid,"node_id":node,"incident_id":inc,"mode":mode,
        "plan":str(plan_path),"plan_sha256":plan_env["payload_sha256"],
        "automation_mode":cfg["automation_mode"],"created_utc":utc_now()
    }
    (root/"RESPONDER_RECORD.json").write_text(json.dumps(record,indent=2,sort_keys=True))

    if cfg["automation_mode"]=="dry-run":
        # Dry-run records a separate description and removes the plan because
        # the operator requested no signed actionable plan.
        plan_path.unlink(missing_ok=True)
        record["status"]="DRY_RUN_ONLY"
    elif cfg["automation_mode"]=="approval":
        record["status"]="WAITING_FOR_APPROVAL"
    elif cfg["automation_mode"]=="auto":
        node_cfg=(cfg.get("nodes") or {}).get(node,{})
        cmd=[
            sys.executable,str(HERE/"execute_containment.py"),
            "--plan",str(plan_path),
            "--plan-public-key",cfg["plan_public_key"],
            "--case-dir",str(root),
            "--containment-private-key",cfg["containment_private_key"],
            "--containment-public-key",cfg["containment_public_key"],
            "--control-file",node_cfg["control_file"],
        ]
        if cfg.get("preservation_signing_key"):
            cmd += ["--preservation-signing-key",cfg["preservation_signing_key"]]
        if node_cfg.get("pid") is not None:
            cmd += ["--pid",str(node_cfg["pid"])]
        if node_cfg.get("model_path"):
            cmd += ["--model-path",node_cfg["model_path"]]
        if cfg.get("skip_runtime_collector"):
            cmd += ["--skip-runtime-collector"]
        for spec in node_cfg.get("copy",[]):cmd += ["--copy",spec]
        for spec in node_cfg.get("reference",[]):cmd += ["--reference",spec]
        cp=subprocess.run(cmd,text=True,capture_output=True)
        (root/"executor.stdout.txt").write_text(cp.stdout or "")
        (root/"executor.stderr.txt").write_text(cp.stderr or "")
        record["executor_returncode"]=cp.returncode
        record["status"]="EXECUTED" if cp.returncode==0 else "EXECUTION_FAILED"
    else:
        raise ValueError("automation_mode must be dry-run, approval, or auto")

    state["handled_alert_ids"].append(aid)
    (root/"RESPONDER_RECORD.json").write_text(json.dumps(record,indent=2,sort_keys=True))
    return record


def run_once(cfg,state_path):
    state=load_state(state_path)
    obj=get_json(cfg["collector_url"].rstrip("/")+"/v1/alerts",cfg.get("collector_ca_file"))
    results=[]
    for alert in sorted(obj.get("alerts",[]),key=lambda x:int(x["id"])):
        if alert.get("severity") not in cfg.get("severities",["critical"]):continue
        r=process_alert(alert,cfg,state)
        if r:results.append(r)
    save_state(state_path,state)
    return results


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--config",required=True);ap.add_argument("--once",action="store_true")
    args=ap.parse_args()
    cfg=json.loads(Path(args.config).read_text())
    state_path=Path(cfg.get("state_file","./auto_responder_state.json"))
    if args.once:
        print(json.dumps(run_once(cfg,state_path),indent=2,sort_keys=True));return
    interval=float(cfg.get("poll_seconds",15))
    while True:
        try:
            r=run_once(cfg,state_path)
            if r:print(json.dumps(r,indent=2,sort_keys=True),flush=True)
        except Exception as e:
            print(json.dumps({"error":repr(e),"timestamp_utc":utc_now()}),flush=True)
        time.sleep(interval)


if __name__=="__main__":
    main()
