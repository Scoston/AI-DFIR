#!/usr/bin/env python3
import argparse, base64, csv, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path


HERE=Path(__file__).resolve().parent


def run(args, env=None):
    cmd=[sys.executable if str(args[0]).endswith(".py") else args[0], *args] if False else args
    print("+"," ".join(map(str,cmd)),flush=True)
    cp=subprocess.run(cmd,text=True,capture_output=True,env=env)
    if cp.stdout: print(cp.stdout)
    if cp.stderr: print(cp.stderr,file=sys.stderr)
    if cp.returncode!=0:
        raise RuntimeError(f"command failed ({cp.returncode}): {cmd}")
    return cp


def py(script,*args,env=None):
    return run([sys.executable,str(HERE/script),*map(str,args)],env=env)


def jwt_part(obj):
    raw=json.dumps(obj,separators=(",",":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    out=Path(args.out).resolve()
    shutil.rmtree(out,ignore_errors=True)
    out.mkdir(parents=True)

    results={}

    # 1. Syntax compile all Python entrypoints.
    for p in HERE.glob("*.py"):
        if p.name.startswith("."):continue
        import py_compile
        py_compile.compile(str(p),doraise=True)
    results["python_compile"]="PASS"

    # 2. Provenance / DSSE / tamper detection.
    prov=out/"provenance"
    py("provenance_bundle.py","selftest","--out",prov)
    pdata=json.loads((prov/"SELFTEST.json").read_text())
    assert pdata["tampered_evidence_rejected"]
    results["signed_provenance"]="PASS"

    # 3. Known-good sparse-depth baseline + localization.
    base=out/"baseline"
    py("baseline_engine.py","selftest","--out",base)
    div=json.loads((base/"score"/"divergence_report.json").read_text())
    assert div["first_material_divergence_depth"]==32
    results["baseline_localization"]="PASS"

    # 4. Runtime model-object inventory / unexpected hook.
    runtime=out/"runtime_inventory"
    py("runtime_inventory.py","selftest","--out",runtime)
    rfind=json.loads((runtime/"findings.json").read_text())
    assert any(x["type"]=="unexpected_hook" for x in rfind)
    results["runtime_hook_inventory"]="PASS"

    # 5. v0.2 approved activation fingerprint synthetic test.
    act=out/"activation"
    py("activation_fingerprint.py","selftest","--out",act)
    results["activation_fingerprint"]="PASS"

    # 6. v0.3 passive live attestation + HMAC/hash-chain corruption rejection.
    live=out/"live"
    py("live_attestation.py","selftest","--out",live)
    ldata=json.loads((live/"SELFTEST.json").read_text())
    assert ldata["corrupt_chain_rejected"]
    results["live_attestation"]="PASS"

    # 7. Summarize live evidence.
    live_summary=out/"live_summary"
    py("summarize_live_attestation.py",
       "--log",live/"attestation.jsonl","--out",live_summary)
    assert (live_summary/"depth_summary.csv").exists()
    results["live_summary"]="PASS"

    # 8. OCSF-aligned export.
    ocsf=out/"ocsf.jsonl"
    py("ocsf_export.py",
       "--attestation-log",live/"attestation.jsonl",
       "--model-name","synthetic-model","--model-provider","selftest",
       "--out",ocsf)
    rows=[json.loads(x) for x in ocsf.read_text().splitlines() if x.strip()]
    assert rows and rows[0]["class_uid"]==1007 and "ai_operation" in rows[0]["metadata"]["profiles"]
    results["ocsf_export"]="PASS"

    # 9. Agent/tool trace.
    agent=out/"agent_trace.jsonl"
    py("agent_trace.py","--log",agent,"--inference-id","INF-SELFTEST",
       "--type","tool_call","--name","synthetic_tool",
       "--content",'{"safe":"test"}',"--authority-id","delegation-selftest")
    arow=json.loads(agent.read_text().splitlines()[0])
    assert arow["content_sha256"] and "safe" not in json.dumps(arow)
    results["agent_trace"]="PASS"

    # 10. GPU attestation ingestion (decode/preserve only; no fake verification).
    now=int(time.time())
    token=jwt_part({"alg":"none","typ":"JWT"})+"."+jwt_part({
        "iss":"https://nras.attestation.nvidia.com",
        "sub":"NVIDIA-PLATFORM-ATTESTATION",
        "iat":now,"exp":now+3600,"nbf":now-10,
        "eat_nonce":"selftest",
        "x-nvidia-overall-att-result":True,
    })+"."
    token_file=out/"gpu_token.jwt";token_file.write_text(token)
    gpu=out/"gpu_attestation.json"
    py("gpu_attestation_ingest.py","--token-file",token_file,
       "--verification-status","unknown","--out",gpu)
    gd=json.loads(gpu.read_text())
    assert gd["overall_attestation_result"] is True
    assert gd["signature_verified_by_this_tool"] is False
    results["gpu_attestation_ingest"]="PASS"

    # 11. Timeline, including a synthetic suspicious runtime artifact access.
    change=out/"change.jsonl"
    t=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    change.write_text(json.dumps({
        "timestamp_utc":t,"event_type":"file_open","name":"/tmp/refusal_direction.pt"
    })+"\n")
    timeline=out/"timeline"
    py("timeline_builder.py",
       "--source",f"live={live/'attestation.jsonl'}",
       "--source",f"agent={agent}",
       "--source",f"runtime={change}",
       "--out",timeline)
    tl=json.loads((timeline/"timeline.json").read_text())
    assert tl["correlated_change_event"] is not None
    results["timeline"]="PASS"

    # 12. Synthetic tensor/low-rank evidence for correlator.
    tensor=out/"tensor_metrics.csv"
    with tensor.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["tensor","status","relative_fro_delta"])
        w.writeheader();w.writerow({"tensor":"x","status":"compared","relative_fro_delta":"0.01"})
    low=out/"low_rank_screen.csv"
    with low.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["tensor","top1_energy_ratio"])
        w.writeheader()
        for i in range(3):w.writerow({"tensor":f"x{i}","top1_energy_ratio":"0.98"})

    # 13. Final evidence correlation should reach level 4.
    corr=out/"correlation.json"
    py("correlate_evidence.py",
       "--divergence-report",base/"score"/"divergence_report.json",
       "--tensor-metrics",tensor,
       "--low-rank-screen",low,
       "--runtime-findings",runtime/"findings.json",
       "--provenance-bundle",prov/"bundle",
       "--timeline-json",timeline/"timeline.json",
       "--out",corr)
    c=json.loads(corr.read_text())
    assert c["confidence_level"]==4
    results["evidence_correlation"]="PASS"

    # 14. Case initializer.
    cases=out/"cases"
    cp=py("case_init.py","--case-id","CASE-SELFTEST","--root",cases)
    assert (cases/"CASE-SELFTEST"/"00_case"/"case.json").exists()
    results["case_init"]="PASS"

    final={"status":"PASS","components":results}
    (out/"V0.4_SELFTEST.json").write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
