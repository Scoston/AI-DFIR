#!/usr/bin/env python3
"""Approved fleet registry: node identities and expected state."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from fleet_crypto import load_public, key_id


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def init_registry(path: Path):
    save({"schema": "ai-dfir/fleet-registry/v0.5", "nodes": {}}, path)


def enroll(path: Path, node_id: str, public_key: Path, policy_file: Path | None):
    reg = load(path) if path.exists() else {"schema":"ai-dfir/fleet-registry/v0.5","nodes":{}}
    pub = load_public(public_key)
    pem = public_key.read_text(encoding="utf-8")
    policy = json.loads(policy_file.read_text()) if policy_file else {
        "approved": {},
        "allowed_adapters": [],
        "approved_hook_fingerprints": [],
        "high_robust_z": 5.0,
        "critical_robust_z": 10.0,
        "require_hardware_attestation": False,
        "recovery_heartbeats": 3,
    }
    reg["nodes"][node_id] = {
        "node_id": node_id,
        "key_id": key_id(pub),
        "public_key_pem": pem,
        "policy": policy,
        "enabled": True,
    }
    save(reg, path)
    print(json.dumps({"enrolled":node_id,"key_id":reg["nodes"][node_id]["key_id"]}, indent=2))


def main():
    ap=argparse.ArgumentParser()
    sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("init");p.add_argument("--registry",required=True)
    p=sp.add_parser("enroll");p.add_argument("--registry",required=True);p.add_argument("--node-id",required=True)
    p.add_argument("--public-key",required=True);p.add_argument("--policy-file")
    p=sp.add_parser("set-enabled");p.add_argument("--registry",required=True);p.add_argument("--node-id",required=True)
    p.add_argument("--enabled",choices=["true","false"],required=True)
    p=sp.add_parser("rotate-key");p.add_argument("--registry",required=True);p.add_argument("--node-id",required=True)
    p.add_argument("--public-key",required=True)
    p=sp.add_parser("show");p.add_argument("--registry",required=True);p.add_argument("--node-id")
    args=ap.parse_args()
    if args.cmd=="init":
        init_registry(Path(args.registry))
    elif args.cmd=="enroll":
        enroll(Path(args.registry),args.node_id,Path(args.public_key),Path(args.policy_file) if args.policy_file else None)
    elif args.cmd=="set-enabled":
        path=Path(args.registry);reg=load(path)
        if args.node_id not in reg["nodes"]: raise KeyError(args.node_id)
        reg["nodes"][args.node_id]["enabled"]=(args.enabled=="true");save(reg,path)
        print(json.dumps({"node_id":args.node_id,"enabled":reg["nodes"][args.node_id]["enabled"]},indent=2))
    elif args.cmd=="rotate-key":
        path=Path(args.registry);reg=load(path)
        if args.node_id not in reg["nodes"]: raise KeyError(args.node_id)
        pub=load_public(Path(args.public_key))
        reg["nodes"][args.node_id]["public_key_pem"]=Path(args.public_key).read_text()
        reg["nodes"][args.node_id]["key_id"]=key_id(pub);save(reg,path)
        print(json.dumps({"node_id":args.node_id,"key_id":reg["nodes"][args.node_id]["key_id"]},indent=2))
    else:
        reg=load(Path(args.registry))
        obj=reg["nodes"].get(args.node_id) if args.node_id else reg
        print(json.dumps(obj,indent=2,sort_keys=True))

if __name__=="__main__":main()
