#!/usr/bin/env python3
"""Standalone convenience verifier for v0.3 attestation logs."""
import os
import sys
from pathlib import Path

# Reuse the canonical verifier so validation logic cannot drift.
from live_attestation import verify_log, load_hmac_key_from_env
import argparse, json

ap = argparse.ArgumentParser()
ap.add_argument("--log", required=True)
ap.add_argument("--require-hmac", action="store_true")
args = ap.parse_args()

key = load_hmac_key_from_env()
ok, info = verify_log(Path(args.log), key, require_hmac=args.require_hmac)
print(json.dumps({"valid": ok, **info}, indent=2, sort_keys=True))
raise SystemExit(0 if ok else 1)
