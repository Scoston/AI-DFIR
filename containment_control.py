#!/usr/bin/env python3
"""
Signed AI containment control document.

Modes:
  observe       - no enforcement, evidence/alert only
  freeze-tools  - model inference allowed, all tool calls denied
  read-only     - model inference allowed; only explicitly non-mutating tools allowed
  quarantine    - new model inference denied
  failover      - local suspect backend denied; route to approved fallback target

The control is signed with Ed25519 and written atomically.
"""
from __future__ import annotations
import argparse, json, os, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path
from fleet_crypto import sign_payload, verify_envelope


VALID_MODES = {"observe","freeze-tools","read-only","quarantine","failover","released"}


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def atomic_write(path: Path, text: str, mode=0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name+".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        # fsync directory so rename is durable.
        dfd=os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def create_control(private_key: Path, out: Path, mode: str, incident_id: str,
                   reason: str, approved_backend: str | None = None,
                   read_only_tools=None, source_alert=None, previous_control_sha256=None):
    if mode not in VALID_MODES:
        raise ValueError(mode)
    if mode=="failover" and not approved_backend:
        raise ValueError("failover requires approved_backend")
    payload={
        "schema":"ai-dfir/containment-control/v0.6",
        "control_id":str(uuid.uuid4()),
        "incident_id":incident_id,
        "created_utc":utc_now(),
        "mode":mode,
        "reason":reason,
        "approved_backend":approved_backend,
        "read_only_tools":sorted(set(read_only_tools or [])),
        "source_alert":source_alert,
        "previous_control_sha256":previous_control_sha256,
    }
    env=sign_payload(private_key,payload)
    atomic_write(out,json.dumps(env,indent=2,sort_keys=True)+"\n")
    return env


def verify_control(public_key: Path, control: Path):
    env=json.loads(control.read_text(encoding="utf-8"))
    return verify_envelope(public_key,env)


def main():
    ap=argparse.ArgumentParser()
    sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("set")
    p.add_argument("--private-key",required=True)
    p.add_argument("--out",required=True)
    p.add_argument("--mode",required=True,choices=sorted(VALID_MODES))
    p.add_argument("--incident-id",required=True)
    p.add_argument("--reason",required=True)
    p.add_argument("--approved-backend")
    p.add_argument("--read-only-tool",action="append",default=[])
    p=sp.add_parser("verify")
    p.add_argument("--public-key",required=True)
    p.add_argument("--control",required=True)
    args=ap.parse_args()
    if args.cmd=="set":
        env=create_control(Path(args.private_key),Path(args.out),args.mode,args.incident_id,
                           args.reason,args.approved_backend,args.read_only_tool)
        print(json.dumps(env,indent=2,sort_keys=True))
    else:
        payload=verify_control(Path(args.public_key),Path(args.control))
        print(json.dumps({"valid":True,"payload":payload},indent=2,sort_keys=True))


if __name__=="__main__":
    main()
