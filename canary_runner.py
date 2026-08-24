#!/usr/bin/env python3
"""
Scheduled safe canary runner.

Runs the existing one-token passive live attestation against a controlled prompt
set, verifies the event chain, then scores it against an approved runtime baseline.
"""
import argparse, json, subprocess, sys
from pathlib import Path


HERE=Path(__file__).resolve().parent


def run(cmd):
    print("+"," ".join(map(str,cmd)),flush=True)
    subprocess.run(cmd,check=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",required=True)
    ap.add_argument("--fingerprint",required=True)
    ap.add_argument("--approved-activations",required=True)
    ap.add_argument("--baseline",required=True)
    ap.add_argument("--prompts",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--depths",default="16,24,32,36,40,44,48,56,64")
    ap.add_argument("--thinking",default="off")
    ap.add_argument("--dtype",default="bf16")
    args=ap.parse_args()
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    log=out/"events.jsonl";head=out/"chain_head.json"
    run([sys.executable,str(HERE/"live_attestation.py"),"probe",
         "--model",args.model,"--local-files-only",
         "--fingerprint",args.fingerprint,
         "--approved-activations",args.approved_activations,
         "--prompts",args.prompts,"--thinking",args.thinking,
         "--dtype",args.dtype,"--depths",args.depths,
         "--log",str(log),"--head",str(head)])
    run([sys.executable,str(HERE/"baseline_engine.py"),"score",
         "--baseline",args.baseline,"--log",str(log),"--out",str(out/"score")])
    print((out/"score"/"divergence_report.json").read_text())


if __name__=="__main__":main()
