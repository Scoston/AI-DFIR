#!/usr/bin/env python3
import json, shutil, sys, threading, time, urllib.request
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from fleet_crypto import generate
from fleet_registry import init_registry, enroll
from fleet_collector import App, make_server
from fleet_agent import dry_run, run_once
from fleet_policy_builder import main as _unused  # compile/import check only


def get_json(url):
    with urllib.request.urlopen(url,timeout=5) as r:
        return json.loads(r.read())


def main():
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    out=Path(args.out).resolve()
    shutil.rmtree(out,ignore_errors=True)
    out.mkdir(parents=True)

    # Identities.
    agent_priv=out/"agent.pem"; agent_pub=out/"agent.pub.pem"
    collector_priv=out/"collector.pem"; collector_pub=out/"collector.pub.pem"
    generate(agent_priv,agent_pub)
    generate(collector_priv,collector_pub)

    # Synthetic approved node evidence.
    model_dir=out/"model"; model_dir.mkdir()
    (model_dir/"weights.safetensors").write_bytes(b"synthetic-approved-model")
    model_manifest=out/"model_manifest.json"; model_manifest.write_text('{"approved":true}')
    fingerprint=out/"fingerprint.safetensors"; fingerprint.write_bytes(b"fingerprint")
    approved_acts=out/"approved_activations.safetensors"; approved_acts.write_bytes(b"activations")
    tokenizer=out/"tokenizer.json"; tokenizer.write_text('{"vocab":"synthetic"}')
    template=out/"chat_template.jinja"; template.write_text("{{ messages }}")
    runtime=out/"runtime.json"
    approved_runtime={
        "hooks":[],
        "adapters":{"active_adapters":[],"peft_configs":[]},
        "config_sha256":"synthetic",
    }
    runtime.write_text(json.dumps(approved_runtime,sort_keys=True))
    state=out/"agent_state.json"
    receipts=out/"receipts"

    cfg={
        "node_id":"node-selftest",
        "private_key":str(agent_priv),
        "collector_url":"http://127.0.0.1:1",  # replaced after server starts
        "collector_public_key":str(collector_pub),
        "require_signed_collector_receipt":True,
        "state_file":str(state),
        "receipt_dir":str(receipts),
        "heartbeat_seconds":0.1,
        "model_dir":str(model_dir),
        "model_manifest":str(model_manifest),
        "fingerprint_file":str(fingerprint),
        "approved_activations_file":str(approved_acts),
        "runtime_inventory":str(runtime),
        "chat_template_file":str(template),
        "tokenizer_file":str(tokenizer),
        "container_image_digest":"sha256:selftest",
        "skip_full_model_hash":False,
        "full_hash_interval_seconds":999999,
        "full_hash_on_metadata_change":True,
    }

    # Derive the enrollment policy from a dry-run observed state.
    dry_path=out/"approved_heartbeat.json"
    env=dry_run(cfg,state)
    dry_path.write_text(json.dumps(env,indent=2,sort_keys=True))
    payload=env["payload"]
    observed=payload["observed"]
    policy={
        "approved":{k:v for k,v in observed.items()
                    if k in (
                        "model_manifest_sha256","model_tree_content_sha256","fingerprint_sha256",
                        "approved_activations_sha256","runtime_inventory_sha256",
                        "container_image_digest","chat_template_sha256","tokenizer_sha256"
                    ) and v is not None},
        "allowed_adapters":observed.get("active_adapters") or [],
        "approved_hook_fingerprints":observed.get("hook_fingerprints") or [],
        "high_robust_z":5.0,
        "critical_robust_z":10.0,
        "require_hardware_attestation":False,
        "recovery_heartbeats":2,
        "expected_heartbeat_seconds":0.1,
    }
    policy_path=out/"policy.json"; policy_path.write_text(json.dumps(policy,indent=2,sort_keys=True))
    registry=out/"registry.json"
    init_registry(registry)
    enroll(registry,"node-selftest",agent_pub,policy_path)

    # Collector with signed receipts.
    db=out/"fleet.db"
    app=App(registry,db,max_clock_skew=300,collector_private_key=collector_priv)
    srv=make_server("127.0.0.1",0,app)
    t=threading.Thread(target=srv.serve_forever,daemon=True);t.start()
    base=f"http://127.0.0.1:{srv.server_port}"
    cfg["collector_url"]=base
    cfg_path=out/"agent_config.json";cfg_path.write_text(json.dumps(cfg,indent=2))

    results={}

    # 1. Healthy first heartbeat + signed receipt verified by the agent.
    run_once(cfg,state)
    fleet=app.fleet_view()
    assert fleet[0]["state"]=="NORMAL",fleet
    assert (receipts/"000000000001.json").exists()
    results["healthy_signed_heartbeat"]="PASS"

    # 2. Collector must reject a replay of the exact signed heartbeat.
    with app.store.conn() as c:
        row=c.execute("SELECT envelope_json FROM heartbeats WHERE node_id=? AND seq=1",
                      ("node-selftest",)).fetchone()
    replay=json.loads(row["envelope_json"])
    rejected=False
    try: app.accept(replay)
    except ValueError: rejected=True
    assert rejected
    results["anti_replay"]="PASS"

    # 3. Unexpected adapter + runtime inventory hash change => CRITICAL.
    bad=dict(approved_runtime)
    bad["adapters"]={"active_adapters":["unapproved-adapter"],"peft_configs":[]}
    runtime.write_text(json.dumps(bad,sort_keys=True))
    run_once(cfg,state)
    fleet=app.fleet_view()
    assert fleet[0]["state"]=="CRITICAL",fleet
    codes={x["code"] for x in fleet[0]["findings"]}
    assert "UNEXPECTED_ADAPTER" in codes
    results["adapter_drift_detection"]="PASS"

    # 4. Restore approved state and exercise recovery hysteresis.
    runtime.write_text(json.dumps(approved_runtime,sort_keys=True))
    run_once(cfg,state)  # recovery streak 1, still critical
    assert app.fleet_view()[0]["state"]=="CRITICAL"
    run_once(cfg,state)  # recovery streak 2 => recovered
    assert app.fleet_view()[0]["state"]=="RECOVERED"
    run_once(cfg,state)  # next clean => normal
    assert app.fleet_view()[0]["state"]=="NORMAL"
    results["recovery_hysteresis"]="PASS"

    # 5. Modify model content. Metadata change forces full content-tree rehash.
    (model_dir/"weights.safetensors").write_bytes(b"synthetic-TAMPERED-model")
    run_once(cfg,state)
    fleet=app.fleet_view()
    assert fleet[0]["state"]=="CRITICAL",fleet
    codes={x["code"] for x in fleet[0]["findings"]}
    assert "MODEL_CONTENT_TREE_DRIFT" in codes
    results["model_content_tree_drift"]="PASS"

    # 6. Alerts and Prometheus endpoints.
    alerts=get_json(base+"/v1/alerts")["alerts"]
    assert alerts and any(a["severity"]=="critical" for a in alerts)
    with urllib.request.urlopen(base+"/metrics",timeout=5) as r:
        metrics=r.read().decode()
    assert "ai_dfir_fleet_node_state" in metrics
    results["alerts_and_metrics"]="PASS"

    # 7. Missing heartbeat/stale state.
    time.sleep(0.30)
    assert app.fleet_view()[0]["state"]=="STALE"
    results["stale_node_detection"]="PASS"

    srv.shutdown();srv.server_close()

    final={"status":"PASS","components":results}
    (out/"V0.5_SELFTEST.json").write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
