#!/usr/bin/env python3
import json, shutil, subprocess, sys, uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from fleet_crypto import generate
from containment_plan import create_plan, approve, verify_approval
from containment_control import verify_control, create_control
from containment_guard import ContainmentGuard, ContainmentDenied
from consequence_reconciler import main as _cr_import
from recovery_gate import create_release_request, approve_release


def run(cmd, expected=(0,)):
    print("+"," ".join(map(str,cmd)),flush=True)
    cp=subprocess.run(cmd,text=True,capture_output=True)
    if cp.stdout: print(cp.stdout)
    if cp.stderr: print(cp.stderr,file=sys.stderr)
    if cp.returncode not in expected:
        raise RuntimeError(f"rc={cp.returncode} expected={expected}: {cmd}")
    return cp


def py(name,*args,expected=(0,)):
    return run([sys.executable,str(HERE/name),*map(str,args)],expected=expected)


def append_trace(path,event):
    with path.open("a") as f:f.write(json.dumps(event)+"\n")


def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True)
    args=ap.parse_args()
    out=Path(args.out).resolve()
    shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)

    # Keys are separated by role.
    keys={}
    for role in ["plan","approver","containment","preservation","release_request"]:
        priv=out/f"{role}.pem";pub=out/f"{role}.pub.pem"
        generate(priv,pub);keys[role]=(priv,pub)

    evidence=out/"synthetic_runtime.json"
    evidence.write_text(json.dumps({"runtime":"approved","hooks":[]},sort_keys=True))
    control=out/"containment.json"
    case=out/"case1"
    incident="AIIR-SELFTEST-1"
    plan=out/"plan.json"
    approval=out/"approval.json"

    # 1. Plan/approval binding.
    env=create_plan(
        keys["plan"][0],plan,incident,"node-1","101","freeze-tools",
        "UNEXPECTED_RUNTIME_HOOK: synthetic test",None,["lookup_ticket"],"abort"
    )
    approve(keys["plan"][1],plan,keys["approver"][0],approval)
    verify_approval(keys["plan"][1],plan,keys["approver"][1],approval)

    # 2. Execute preservation-first containment with approval.
    cp=py("execute_containment.py",
          "--plan",plan,
          "--plan-public-key",keys["plan"][1],
          "--require-approval",
          "--approval",approval,
          "--approver-public-key",keys["approver"][1],
          "--case-dir",case,
          "--containment-private-key",keys["containment"][0],
          "--containment-public-key",keys["containment"][1],
          "--control-file",control,
          "--preservation-signing-key",keys["preservation"][0],
          "--copy",f"runtime={evidence}",
          "--skip-runtime-collector")
    result=json.loads((case/"EXECUTION_RESULT.json").read_text())
    assert result["containment_applied"] is True
    assert (case/"pre_preservation"/"signed_seal"/"BUNDLE_HEAD.json").exists()
    assert (case/"post_preservation"/"signed_seal"/"BUNDLE_HEAD.json").exists()

    # 3. Guard enforces freeze-tools but permits inference.
    guard=ContainmentGuard(control,keys["containment"][1],fail_closed=True)
    assert guard.allow_inference() is True
    denied=False
    try: guard.authorize_tool("lookup_ticket",mutating=False)
    except ContainmentDenied: denied=True
    assert denied
    components={"preservation_first_transaction":"PASS","freeze_tools_enforced":"PASS"}

    # 4. Failover routing + local inference denial.
    create_control(keys["containment"][0],control,"failover",incident,
                   "synthetic failover","https://approved-backend.example")
    guard=ContainmentGuard(control,keys["containment"][1],fail_closed=True)
    assert guard.routing_target("http://suspect")=="https://approved-backend.example"
    denied=False
    try:guard.allow_inference()
    except ContainmentDenied:denied=True
    assert denied
    components["failover_guard"]="PASS"

    # Return to quarantine for recovery workflow.
    create_control(keys["containment"][0],control,"quarantine",incident,"synthetic quarantine")

    # 5. Open downstream consequence blocks release.
    trace=out/"trace.jsonl"
    consequence_id=str(uuid.uuid4())
    append_trace(trace,{
        "event_type":"consequence","event_id":consequence_id,"timestamp_utc":"2026-08-23T00:00:00Z",
        "name":"account_disabled","content_sha256":"abc","authority_id":"a1","parent_id":"p1","metadata":{}
    })
    open_json=out/"open_consequences.json"
    py("consequence_reconciler.py","--trace",trace,"--out",open_json)
    assert json.loads(open_json.read_text())["open_count"]==1

    release_req=out/"release_request.json"
    release_app=out/"release_approval.json"
    create_release_request(
        keys["release_request"][0],release_req,incident,"node-1",control,
        [{"name":"fleet_state_clean","passed":True},
         {"name":"canary_clean","passed":True},
         {"name":"runtime_inventory_clean","passed":True}]
    )
    approve_release(keys["release_request"][1],release_req,keys["approver"][0],release_app)
    cp=py("recovery_gate.py","execute",
          "--release-request",release_req,
          "--request-public-key",keys["release_request"][1],
          "--release-approval",release_app,
          "--approver-public-key",keys["approver"][1],
          "--containment-private-key",keys["containment"][0],
          "--containment-public-key",keys["containment"][1],
          "--control-file",control,
          "--open-consequences",open_json,
          expected=(1,))
    assert verify_control(keys["containment"][1],control)["mode"]=="quarantine"
    components["open_consequence_blocks_release"]="PASS"

    # 6. Close consequence, regenerate release request because control remains same.
    append_trace(trace,{
        "event_type":"containment","event_id":str(uuid.uuid4()),"timestamp_utc":"2026-08-23T00:01:00Z",
        "name":"account_restored","metadata":{"closes_event_id":consequence_id}
    })
    py("consequence_reconciler.py","--trace",trace,"--out",open_json)
    assert json.loads(open_json.read_text())["open_count"]==0
    py("recovery_gate.py","execute",
       "--release-request",release_req,
       "--request-public-key",keys["release_request"][1],
       "--release-approval",release_app,
       "--approver-public-key",keys["approver"][1],
       "--containment-private-key",keys["containment"][0],
       "--containment-public-key",keys["containment"][1],
       "--control-file",control,
       "--open-consequences",open_json)
    assert verify_control(keys["containment"][1],control)["mode"]=="released"
    guard=ContainmentGuard(control,keys["containment"][1],fail_closed=True)
    assert guard.allow_inference() is True
    assert guard.authorize_tool("anything",mutating=True) is True
    components["signed_recovery_release"]="PASS"

    # 7. Preservation failure defaults to ABORT with no new containment file.
    bad_control=out/"bad_control.json"
    bad_plan=out/"bad_plan.json"
    bad_incident="AIIR-SELFTEST-ABORT"
    create_plan(keys["plan"][0],bad_plan,bad_incident,"node-1","102","quarantine",
                "synthetic preservation failure",None,[],"abort")
    bad_case=out/"bad_case"
    cp=py("execute_containment.py",
          "--plan",bad_plan,"--plan-public-key",keys["plan"][1],
          "--case-dir",bad_case,
          "--containment-private-key",keys["containment"][0],
          "--containment-public-key",keys["containment"][1],
          "--control-file",bad_control,
          "--copy","missing=/definitely/not/present",
          "--skip-runtime-collector",
          expected=(2,))
    assert not bad_control.exists()
    components["preservation_failure_aborts_by_default"]="PASS"

    # 8. Explicit contain_anyway overrides evidence-preservation failure.
    override_control=out/"override_control.json"
    override_plan=out/"override_plan.json"
    override_incident="AIIR-SELFTEST-OVERRIDE"
    create_plan(keys["plan"][0],override_plan,override_incident,"node-1","103","quarantine",
                "synthetic urgent override",None,[],"contain_anyway")
    override_case=out/"override_case"
    py("execute_containment.py",
       "--plan",override_plan,"--plan-public-key",keys["plan"][1],
       "--case-dir",override_case,
       "--containment-private-key",keys["containment"][0],
       "--containment-public-key",keys["containment"][1],
       "--control-file",override_control,
       "--copy","missing=/definitely/not/present",
       "--skip-runtime-collector")
    assert verify_control(keys["containment"][1],override_control)["mode"]=="quarantine"
    components["explicit_contain_anyway_override"]="PASS"

    # 9. Tamper with containment control => fail-closed guard.
    env=json.loads(override_control.read_text())
    env["payload"]["mode"]="released"
    override_control.write_text(json.dumps(env))
    guard=ContainmentGuard(override_control,keys["containment"][1],fail_closed=True)
    denied=False
    try:guard.allow_inference()
    except ContainmentDenied:denied=True
    assert denied
    components["tampered_control_fail_closed"]="PASS"

    final={"status":"PASS","components":components}
    (out/"V0.6_SELFTEST.json").write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
