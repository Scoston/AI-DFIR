#!/usr/bin/env python3
"""Verify an approved failover backend before applying failover containment."""
import argparse, hashlib, json, ssl, urllib.request
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--url",required=True,help="Health/attestation URL")
    ap.add_argument("--ca-file")
    ap.add_argument("--expected-json",help="JSON object of exact required top-level fields")
    ap.add_argument("--expected-body-sha256")
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    ctx=ssl.create_default_context(cafile=args.ca_file) if args.url.startswith("https://") else None
    with urllib.request.urlopen(args.url,timeout=10,context=ctx) as r:
        body=r.read()
        status=r.status
    digest=hashlib.sha256(body).hexdigest()
    parsed=None
    try: parsed=json.loads(body)
    except Exception: pass
    checks={"http_2xx":200<=status<300}
    if args.expected_body_sha256:
        checks["body_sha256"]=digest==args.expected_body_sha256
    if args.expected_json:
        want=json.loads(Path(args.expected_json).read_text())
        checks["json_fields"]=bool(parsed is not None and all(parsed.get(k)==v for k,v in want.items()))
    result={
        "schema":"ai-dfir/failover-precheck/v0.6",
        "url":args.url,"http_status":status,"body_sha256":digest,
        "checks":checks,"approved":all(checks.values())
    }
    Path(args.out).parent.mkdir(parents=True,exist_ok=True)
    Path(args.out).write_text(json.dumps(result,indent=2,sort_keys=True))
    print(json.dumps(result,indent=2,sort_keys=True))
    if not result["approved"]:raise SystemExit(2)

if __name__=="__main__":main()
