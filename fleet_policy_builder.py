#!/usr/bin/env python3
"""Create an approved node policy from a signed fleet-agent dry-run heartbeat."""
import argparse, json
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--heartbeat-envelope",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--expected-heartbeat-seconds",type=float,default=300)
    ap.add_argument("--high-robust-z",type=float,default=5.0)
    ap.add_argument("--critical-robust-z",type=float,default=10.0)
    ap.add_argument("--recovery-heartbeats",type=int,default=3)
    ap.add_argument("--require-hardware-attestation",action="store_true")
    args=ap.parse_args()
    env=json.loads(Path(args.heartbeat_envelope).read_text())
    payload=env["payload"]
    observed=payload.get("observed",{})
    exact={}
    for k in [
        "model_manifest_sha256","model_tree_content_sha256","fingerprint_sha256",
        "approved_activations_sha256","runtime_inventory_sha256",
        "container_image_digest","chat_template_sha256","tokenizer_sha256",
        "authority_policy_sha256","tool_schema_sha256","retrieval_config_sha256"
    ]:
        if observed.get(k) is not None: exact[k]=observed[k]
    policy={
        "approved":exact,
        "allowed_adapters":observed.get("active_adapters") or [],
        "approved_hook_fingerprints":observed.get("hook_fingerprints") or [],
        "high_robust_z":args.high_robust_z,
        "critical_robust_z":args.critical_robust_z,
        "require_hardware_attestation":args.require_hardware_attestation,
        "recovery_heartbeats":args.recovery_heartbeats,
        "expected_heartbeat_seconds":args.expected_heartbeat_seconds,
    }
    Path(args.out).write_text(json.dumps(policy,indent=2,sort_keys=True))
    print(json.dumps(policy,indent=2,sort_keys=True))


if __name__=="__main__":main()
