#!/usr/bin/env python3
"""
Controlled forensic replay wrapper.

Replays the SAME probe set against approved and suspect checkpoints using the
existing v0.2 activation extractor, derives the fingerprint only from approved,
then compares and automatically summarizes the first large matched-activation jump.

This cannot reproduce a runtime-only intervention unless the suspect execution
environment/intervention is also reproduced.
"""
from __future__ import annotations
import argparse, csv, json, subprocess, sys
from pathlib import Path


def run(cmd):
    print("+"," ".join(str(x) for x in cmd),flush=True)
    subprocess.run(cmd,check=True)


def summarize(compare_dir: Path, out: Path):
    path=compare_dir/"matched_activation_delta.csv"
    rows=[]
    with path.open(newline="",encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({
                "depth":int(r["depth"]),
                "cos":float(r["mean_prompt_cosine_similarity"]),
                "rel":float(r["mean_relative_l2_delta"]),
            })
    # Threshold-free jump localization: rank largest increases in relative L2.
    jumps=[]
    for a,b in zip(rows,rows[1:]):
        jumps.append({
            "from_depth":a["depth"],"to_depth":b["depth"],
            "relative_l2_jump":b["rel"]-a["rel"],
            "cosine_drop":a["cos"]-b["cos"],
        })
    jumps.sort(key=lambda x:(x["relative_l2_jump"]+x["cosine_drop"]),reverse=True)
    result={
        "schema":"ai-dfir/replay-summary/v0.4",
        "largest_transition":jumps[0] if jumps else None,
        "worst_cosine_depth":min(rows,key=lambda r:r["cos"]) if rows else None,
        "highest_relative_l2_depth":max(rows,key=lambda r:r["rel"]) if rows else None,
        "note":"Transition ranking is descriptive and threshold-free; use approved runtime baselines for anomaly thresholds.",
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"replay_summary.json").write_text(json.dumps(result,indent=2,sort_keys=True))
    md=[
        "# AI-DFIR Controlled Replay Report","",
        f"- Largest representation transition: **{result['largest_transition']}**",
        f"- Worst cosine depth: **{result['worst_cosine_depth']}**",
        f"- Highest relative-L2 depth: **{result['highest_relative_l2_depth']}**","",
        "This replay establishes checkpoint-level differential behavior under a controlled inference stack. "
        "It does not establish that a runtime-only production hook existed unless that runtime condition is reproduced.",""
    ]
    (out/"replay_report.md").write_text("\n".join(md))
    print(json.dumps(result,indent=2))


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--approved-model",required=True)
    ap.add_argument("--suspect-model",required=True)
    ap.add_argument("--prompts",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--dtype",default="bf16",choices=["auto","bf16","fp16","fp32"])
    ap.add_argument("--thinking",default="off",choices=["off","on","default"])
    args=ap.parse_args()
    root=Path(args.out).resolve();root.mkdir(parents=True,exist_ok=True)
    here=Path(__file__).resolve().parent
    act=here/"activation_fingerprint.py"

    approved=root/"approved_activations"
    fingerprint=root/"fingerprint"
    suspect=root/"suspect_activations"
    comp=root/"comparison"

    run([sys.executable,str(act),"extract","--model",args.approved_model,
         "--local-files-only","--prompts",args.prompts,"--thinking",args.thinking,
         "--dtype",args.dtype,"--out",str(approved)])
    run([sys.executable,str(act),"derive","--approved-activations",str(approved),"--out",str(fingerprint)])
    run([sys.executable,str(act),"extract","--model",args.suspect_model,
         "--local-files-only","--prompts",args.prompts,"--thinking",args.thinking,
         "--dtype",args.dtype,"--out",str(suspect)])
    run([sys.executable,str(act),"compare","--fingerprint",str(fingerprint),
         "--reference-activations",str(approved),"--suspect-activations",str(suspect),
         "--out",str(comp)])
    summarize(comp,root)

if __name__=="__main__":main()
