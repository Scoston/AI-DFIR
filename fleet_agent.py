#!/usr/bin/env python3
"""AI-DFIR v0.5 node agent: signed continuous fleet heartbeats."""
from __future__ import annotations
import argparse, hashlib, json, os, socket, time, urllib.request, urllib.error, ssl
from datetime import datetime, timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope
from live_attestation import verify_log


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def sha256_file(path: Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(8*1024*1024),b""):h.update(b)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":")).encode()


def metadata_tree(directory: Path):
    rows=[]
    if not directory.exists():return None
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            st=p.stat()
            rows.append([str(p.relative_to(directory)),st.st_size,st.st_mtime_ns])
    return hashlib.sha256(canonical(rows)).hexdigest()


def content_tree(directory: Path):
    """Expensive full-content tree hash. Use on change or slow cadence."""
    rows=[]
    if not directory.exists(): return None
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            rows.append([
                str(p.relative_to(directory)),
                p.stat().st_size,
                sha256_file(p),
            ])
    return hashlib.sha256(canonical(rows)).hexdigest()


def read_json(path):
    p=Path(path) if path else None
    if not p or not p.exists():return None
    return json.loads(p.read_text(encoding="utf-8"))


def hook_fingerprints(runtime):
    fps=[]
    if not runtime:return fps
    for h in runtime.get("hooks",[]):
        cb=h.get("callback",{})
        raw={
            "module_name":h.get("module_name"),
            "hook_kind":h.get("hook_kind"),
            "qualname":cb.get("qualname"),
            "source_sha256":cb.get("source_sha256"),
            "repr_sha256":cb.get("repr_sha256"),
        }
        fps.append(hashlib.sha256(canonical(raw)).hexdigest())
    return sorted(fps)


def load_state(path: Path):
    if path.exists():return json.loads(path.read_text())
    return {"seq":0,"last_payload_sha256":"0"*64,"last_metadata_tree":None,"last_full_hash_utc":None}


def save_state(path: Path,state):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(state,indent=2,sort_keys=True))
    os.replace(tmp,path)


def post_json(url,obj,timeout,ca_file=None,client_cert=None,client_key=None):
    data=json.dumps(obj,sort_keys=True).encode()
    req=urllib.request.Request(url,data=data,headers={"Content-Type":"application/json"},method="POST")
    ctx=None
    if url.lower().startswith("https://"):
        ctx=ssl.create_default_context(cafile=ca_file)
        if client_cert:
            ctx.load_cert_chain(client_cert,client_key)
    with urllib.request.urlopen(req,timeout=timeout,context=ctx) as r:
        return json.loads(r.read())


def build_payload(cfg,state):
    runtime=read_json(cfg.get("runtime_inventory"))
    divergence=read_json(cfg.get("divergence_report")) or {}
    hardware=read_json(cfg.get("hardware_attestation")) or {}
    chain_valid=None
    chain_info={}
    if cfg.get("attestation_log") and Path(cfg["attestation_log"]).exists():
        key=None
        if cfg.get("attestation_hmac_key_hex"):
            key=bytes.fromhex(cfg["attestation_hmac_key_hex"])
        chain_valid,chain_info=verify_log(
            Path(cfg["attestation_log"]),key,
            require_hmac=bool(cfg.get("require_attestation_hmac",False))
        )

    model_dir=Path(cfg["model_dir"]) if cfg.get("model_dir") else None
    tree=metadata_tree(model_dir) if model_dir else None
    changed=(state.get("last_metadata_tree") is not None and tree != state.get("last_metadata_tree"))

    full_tree = state.get("last_full_content_tree")
    full_hash_performed = False
    if model_dir and not cfg.get("skip_full_model_hash", False):
        interval = float(cfg.get("full_hash_interval_seconds", 86400))
        last_epoch = float(state.get("last_full_hash_epoch") or 0)
        due = (time.time() - last_epoch) >= interval
        on_change = bool(cfg.get("full_hash_on_metadata_change", True)) and changed
        if full_tree is None or due or on_change:
            full_tree = content_tree(model_dir)
            full_hash_performed = True

    observed={
        "model_manifest_sha256": sha256_file(Path(cfg["model_manifest"])) if cfg.get("model_manifest") and Path(cfg["model_manifest"]).exists() else None,
        "model_tree_content_sha256": full_tree,
        "fingerprint_sha256": sha256_file(Path(cfg["fingerprint_file"])) if cfg.get("fingerprint_file") and Path(cfg["fingerprint_file"]).exists() else None,
        "approved_activations_sha256": sha256_file(Path(cfg["approved_activations_file"])) if cfg.get("approved_activations_file") and Path(cfg["approved_activations_file"]).exists() else None,
        "runtime_inventory_sha256": sha256_file(Path(cfg["runtime_inventory"])) if cfg.get("runtime_inventory") and Path(cfg["runtime_inventory"]).exists() else None,
        "container_image_digest": cfg.get("container_image_digest"),
        "chat_template_sha256": sha256_file(Path(cfg["chat_template_file"])) if cfg.get("chat_template_file") and Path(cfg["chat_template_file"]).exists() else None,
        "tokenizer_sha256": sha256_file(Path(cfg["tokenizer_file"])) if cfg.get("tokenizer_file") and Path(cfg["tokenizer_file"]).exists() else None,
        "authority_policy_sha256": sha256_file(Path(cfg["authority_policy_file"])) if cfg.get("authority_policy_file") and Path(cfg["authority_policy_file"]).exists() else None,
        "tool_schema_sha256": sha256_file(Path(cfg["tool_schema_file"])) if cfg.get("tool_schema_file") and Path(cfg["tool_schema_file"]).exists() else None,
        "retrieval_config_sha256": sha256_file(Path(cfg["retrieval_config_file"])) if cfg.get("retrieval_config_file") and Path(cfg["retrieval_config_file"]).exists() else None,
        "active_adapters": (runtime or {}).get("adapters",{}).get("active_adapters") or [],
        "hook_fingerprints": hook_fingerprints(runtime),
    }
    payload={
        "schema":"ai-dfir/fleet-heartbeat/v0.5",
        "node_id":cfg["node_id"],
        "seq":int(state["seq"])+1,
        "timestamp_utc":utc_now(),
        "hostname":socket.gethostname(),
        "prev_heartbeat_hash":state.get("last_payload_sha256","0"*64),
        "agent":{"version":"0.5","pid":os.getpid()},
        "observed":observed,
        "quick_integrity":{
            "model_metadata_tree_sha256":tree,
            "metadata_tree_changed":changed,
            "full_content_tree_hash_performed":full_hash_performed,
        },
        "divergence":{
            "first_material_divergence_depth":divergence.get("first_material_divergence_depth"),
            "highest_anomaly_depth":divergence.get("highest_anomaly_depth"),
            "highest_abs_robust_z":divergence.get("highest_abs_robust_z"),
        },
        "attestation_chain":{
            "valid":chain_valid,
            "event_count":chain_info.get("event_count"),
            "last_event_hash":chain_info.get("last_event_hash"),
            "log_sha256":chain_info.get("log_sha256"),
        },
        "hardware_attestation":{
            "verification_status":hardware.get("external_verification_status"),
            "overall_result":hardware.get("overall_attestation_result"),
            "token_sha256":hardware.get("token_sha256"),
        },
    }
    return payload,tree,full_tree,full_hash_performed


def dry_run(cfg,state_path):
    state=load_state(state_path)
    payload,tree,full_tree,full_hash_performed=build_payload(cfg,state)
    envelope=sign_payload(Path(cfg["private_key"]),payload)
    print(json.dumps(envelope,indent=2,sort_keys=True))
    return envelope


def run_once(cfg,state_path):
    state=load_state(state_path)
    payload,tree,full_tree,full_hash_performed=build_payload(cfg,state)
    envelope=sign_payload(Path(cfg["private_key"]),payload)
    response=post_json(
        cfg["collector_url"].rstrip("/")+"/v1/heartbeat",
        envelope,float(cfg.get("http_timeout_seconds",15)),
        ca_file=cfg.get("collector_ca_file"),
        client_cert=cfg.get("client_cert_file"),
        client_key=cfg.get("client_key_file"),
    )
    signed_receipt=response.get("signed_receipt")
    if signed_receipt is not None and cfg.get("collector_public_key"):
        verify_envelope(Path(cfg["collector_public_key"]),signed_receipt)
    elif cfg.get("require_signed_collector_receipt") and signed_receipt is None:
        raise RuntimeError("Collector did not return required signed receipt")
    receipt_dir=Path(cfg.get("receipt_dir",state_path.parent/"receipts"))
    receipt_dir.mkdir(parents=True,exist_ok=True)
    (receipt_dir/f'{payload["seq"]:012d}.json').write_text(json.dumps(response,indent=2,sort_keys=True))

    state["seq"]=payload["seq"]
    state["last_payload_sha256"]=envelope["payload_sha256"]
    state["last_metadata_tree"]=tree
    if full_hash_performed:
        state["last_full_content_tree"]=full_tree
        state["last_full_hash_epoch"]=time.time()
        state["last_full_hash_utc"]=utc_now()
    save_state(state_path,state)
    print(json.dumps({
        "node_id":cfg["node_id"],"seq":payload["seq"],
        "payload_sha256":envelope["payload_sha256"],"collector_response":response
    },indent=2,sort_keys=True))
    return response


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--config",required=True)
    ap.add_argument("--once",action="store_true")
    ap.add_argument("--dry-run",action="store_true",help="Build/sign a heartbeat without sending or incrementing state")
    args=ap.parse_args()
    cfg=json.loads(Path(args.config).read_text())
    state_path=Path(cfg.get("state_file","./fleet_agent_state.json"))
    if args.dry_run:
        dry_run(cfg,state_path);return
    if args.once:
        run_once(cfg,state_path);return
    interval=float(cfg.get("heartbeat_seconds",300))
    while True:
        try:run_once(cfg,state_path)
        except Exception as e:print(json.dumps({"error":repr(e),"timestamp_utc":utc_now()}),flush=True)
        time.sleep(interval)

if __name__=="__main__":main()
