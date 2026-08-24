#!/usr/bin/env python3
"""
Correlate AI-DFIR evidence into confidence levels.

No single signal is treated as proof of abliteration. The result uses the
four-level evidentiary model:
1 behavioral/mechanistic anomaly
2 artifact/runtime anomaly
3 mechanistic + artifact correlation
4 provenance/timeline + mechanistic correlation
"""
import argparse, csv, json
from pathlib import Path


def load_json(p):
    return json.loads(Path(p).read_text()) if p else None


def read_csv(p):
    if not p:return []
    with open(p,newline="",encoding="utf-8") as f:return list(csv.DictReader(f))


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--divergence-report")
    ap.add_argument("--tensor-metrics")
    ap.add_argument("--low-rank-screen")
    ap.add_argument("--runtime-findings")
    ap.add_argument("--behavior-json")
    ap.add_argument("--provenance-bundle")
    ap.add_argument("--timeline-json")
    ap.add_argument("--out",required=True)
    args=ap.parse_args()

    evidence=[]
    divergence=load_json(args.divergence_report) if args.divergence_report else None
    if divergence and divergence.get("first_material_divergence_depth") is not None:
        evidence.append({"signal":"activation_divergence","strength":2,
                         "detail":divergence.get("first_material_divergence_depth")})

    tensors=read_csv(args.tensor_metrics)
    changed=[]
    for r in tensors:
        try:
            if r.get("status")=="compared" and float(r.get("relative_fro_delta",0))>0:
                changed.append(r)
        except: pass
    if changed:
        evidence.append({"signal":"checkpoint_tensor_changes","strength":2,"detail":len(changed)})

    lr=read_csv(args.low_rank_screen)
    low=[]
    for r in lr:
        try:
            if float(r.get("top1_energy_ratio",0))>=0.9: low.append(r)
        except: pass
    if len(low)>=3:
        evidence.append({"signal":"repeated_low_rank_delta_signature","strength":2,"detail":len(low)})

    rf=load_json(args.runtime_findings) if args.runtime_findings else []
    runtime_flags=[x for x in (rf or []) if x.get("type") in
                   ("unexpected_hook","unexpected_adapter_config","active_adapters_changed","adapter_config_changed")]
    if runtime_flags:
        evidence.append({"signal":"unexpected_runtime_intervention","strength":3,"detail":len(runtime_flags)})

    behavior=load_json(args.behavior_json) if args.behavior_json else None
    if behavior and behavior.get("material_anomaly"):
        evidence.append({"signal":"behavioral_anomaly","strength":1,"detail":behavior})

    prov=False
    if args.provenance_bundle:
        head=Path(args.provenance_bundle)/"BUNDLE_HEAD.json"
        prov=head.exists()
        if prov:evidence.append({"signal":"signed_provenance_bundle_present","strength":1,"detail":str(head)})

    timeline=load_json(args.timeline_json) if args.timeline_json else None
    if timeline and timeline.get("correlated_change_event"):
        evidence.append({"signal":"timeline_correlation","strength":3,"detail":timeline["correlated_change_event"]})

    names={e["signal"] for e in evidence}
    level=0
    rationale=[]
    if "activation_divergence" in names or "behavioral_anomaly" in names:
        level=1;rationale.append("Behavioral/mechanistic anomaly present.")
    if "checkpoint_tensor_changes" in names or "unexpected_runtime_intervention" in names:
        level=max(level,2);rationale.append("Artifact or runtime integrity anomaly present.")
    if ("activation_divergence" in names and
        ("checkpoint_tensor_changes" in names or "unexpected_runtime_intervention" in names)):
        level=max(level,3);rationale.append("Mechanistic anomaly correlates with artifact/runtime anomaly.")
    if level>=3 and prov and "timeline_correlation" in names:
        level=4;rationale.append("Signed provenance and timeline correlate the intervention with execution change.")

    attribution="model-integrity anomaly"
    if level>=3 and "repeated_low_rank_delta_signature" in names:
        attribution="directional model-modification pattern consistent with low-dimensional editing"
    if level>=3 and "unexpected_runtime_intervention" in names and not changed:
        attribution="runtime-only model-behavior intervention"

    result={
        "schema":"ai-dfir/evidence-correlation/v0.4",
        "confidence_level":level,
        "finding":attribution,
        "evidence":evidence,
        "rationale":rationale,
        "warning":"This is evidence correlation, not a universal proof of a specific modification technique.",
    }
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True))
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":main()
