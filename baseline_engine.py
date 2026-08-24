#!/usr/bin/env python3
"""
Known-good runtime baseline and automatic divergence localization.

Build baselines only from approved executions with equivalent:
checkpoint, quantization/dtype, tokenizer/chat template, thinking mode,
serving framework/version, probe set, and attestation depths.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

TARGET_METRICS = [
    "cosine_to_exact_approved_activation",
    "relative_l2_to_exact_approved_activation",
    "projection_delta_from_exact_approved",
    "projection_on_approved_direction",
]


def percentile(values, q):
    xs = sorted(values)
    if not xs:
        return None
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs)-1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return xs[lo]
    return xs[lo]*(hi-pos) + xs[hi]*(pos-lo)


def median_abs_dev(values):
    if not values:
        return None
    med = statistics.median(values)
    return statistics.median([abs(x-med) for x in values])


def load_events(paths):
    events = []
    for path in paths:
        with Path(path).open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                e = json.loads(line)
                if e.get("event_type") == "activation_attestation" and e.get("status") == "ok":
                    events.append(e)
    return events


def build_baseline(logs, out):
    events = load_events(logs)
    values = defaultdict(lambda: defaultdict(list))
    contexts = set()

    for e in events:
        contexts.add((
            e.get("model_ref"), e.get("model_revision"),
            e.get("fingerprint_sha256"), e.get("approved_activations_sha256"),
            e.get("thinking"),
        ))
        for depth, m in e.get("measurements", {}).items():
            depth = int(depth)
            for metric in TARGET_METRICS:
                v = m.get(metric)
                if isinstance(v, (int, float)):
                    # Projection delta is centered around zero; model absolute
                    # magnitude separately at score time as needed.
                    values[depth][metric].append(float(v))

    stats = {}
    for depth, metrics in values.items():
        stats[str(depth)] = {}
        for metric, xs in metrics.items():
            med = statistics.median(xs)
            mad = median_abs_dev(xs)
            mean = statistics.mean(xs)
            std = statistics.stdev(xs) if len(xs) >= 2 else 0.0
            stats[str(depth)][metric] = {
                "n": len(xs),
                "median": med,
                "mad": mad,
                "mean": mean,
                "std": std,
                "q01": percentile(xs, .01),
                "q05": percentile(xs, .05),
                "q95": percentile(xs, .95),
                "q99": percentile(xs, .99),
                "min": min(xs),
                "max": max(xs),
            }

    baseline = {
        "schema": "ai-dfir/runtime-baseline/v0.4",
        "approved_event_count": len(events),
        "contexts": [list(x) for x in sorted(contexts, key=str)],
        "depths": stats,
        "note": "Use only when contexts are operationally equivalent.",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote baseline: {out}")


def robust_z(x, s):
    med = s["median"]
    mad = s["mad"] or 0.0
    # 1.4826 converts MAD to a normal-consistent sigma estimate.
    robust_sigma = 1.4826 * mad
    if robust_sigma > 1e-12:
        return (x-med) / robust_sigma, "mad"
    std = s["std"] or 0.0
    if std > 1e-12:
        return (x-s["mean"]) / std, "std"
    return (0.0 if abs(x-med) <= 1e-12 else math.copysign(float("inf"), x-med)), "degenerate"


def score_log(baseline_path, log_path, out_dir, z_threshold=5.0, min_consecutive=2):
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    events = load_events([log_path])
    rows = []
    depth_max = defaultdict(float)
    depth_metric = {}

    for e in events:
        for depth_raw, m in e.get("measurements", {}).items():
            depth = int(depth_raw)
            bdepth = baseline["depths"].get(str(depth), {})
            for metric in TARGET_METRICS:
                if metric not in m or metric not in bdepth:
                    continue
                x = float(m[metric])
                z, method = robust_z(x, bdepth[metric])
                az = abs(z)
                rows.append({
                    "request_id": e.get("request_id"),
                    "prompt_id": e.get("prompt_id"),
                    "depth": depth,
                    "metric": metric,
                    "value": x,
                    "baseline_median": bdepth[metric]["median"],
                    "baseline_mad": bdepth[metric]["mad"],
                    "robust_z": z,
                    "abs_robust_z": az,
                    "scoring_method": method,
                    "anomalous": az >= z_threshold,
                })
                if az > depth_max[depth]:
                    depth_max[depth] = az
                    depth_metric[depth] = metric

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "anomaly_events.csv"
    fields = list(rows[0]) if rows else [
        "request_id","prompt_id","depth","metric","value","baseline_median",
        "baseline_mad","robust_z","abs_robust_z","scoring_method","anomalous"
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    depths = sorted(depth_max)
    flagged = [d for d in depths if depth_max[d] >= z_threshold]

    # First run of at least min_consecutive anomalous OBSERVED depths.
    # Attestation commonly samples sparse depths (e.g. 16,24,32,...), so adjacency
    # means adjacent entries in the selected-depth sequence, not numeric d+1.
    first_div = None
    region = []
    current = []
    for d in depths:
        if depth_max[d] >= z_threshold:
            current.append(d)
            if len(current) >= min_consecutive and first_div is None:
                first_div = current[0]
                region = list(current)
        else:
            if first_div is not None:
                break
            current = []

    if first_div is not None:
        region = []
        active = False
        for d in depths:
            if d == first_div:
                active = True
            if not active:
                continue
            if depth_max[d] >= z_threshold:
                region.append(d)
            else:
                break

    max_depth = max(depths, key=lambda d: depth_max[d]) if depths else None
    result = {
        "schema": "ai-dfir/divergence-localization/v0.4",
        "z_threshold": z_threshold,
        "min_consecutive_depths": min_consecutive,
        "events_scored": len(events),
        "first_material_divergence_depth": first_div,
        "anomalous_region": region,
        "highest_anomaly_depth": max_depth,
        "highest_abs_robust_z": depth_max.get(max_depth) if max_depth is not None else None,
        "highest_anomaly_metric": depth_metric.get(max_depth),
        "flagged_depths": flagged,
        "depth_max_abs_z": {str(k): v for k, v in sorted(depth_max.items())},
    }
    (out_dir / "divergence_report.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )

    md = [
        "# Automatic Runtime Divergence Localization",
        "",
        f"- Events scored: **{len(events)}**",
        f"- Robust-z threshold: **{z_threshold}**",
        f"- First material divergence depth: **{first_div}**",
        f"- Highest anomaly depth: **{max_depth}**",
        f"- Highest absolute robust z: **{result['highest_abs_robust_z']}**",
        "",
        "## Investigator interpretation",
        "",
        "This is a statistical anomaly locator, not standalone attribution. Correlate the "
        "reported region with static tensor changes, unexpected adapters/hooks, process evidence, "
        "and timeline events.",
        "",
    ]
    (out_dir / "divergence_report.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


def selftest(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    approved_logs = []
    for run in range(8):
        p = out / f"approved_{run}.jsonl"
        rows = []
        for depth in [8, 16, 24, 32, 40, 48]:
            # deterministic slight baseline variation
            eps = (run - 3.5) * 0.0002
            m = {
                "cosine_to_exact_approved_activation": 0.999 + eps,
                "relative_l2_to_exact_approved_activation": 0.002 + abs(eps),
                "projection_delta_from_exact_approved": eps,
                "projection_on_approved_direction": 1.0 + eps,
            }
            rows.append((depth, m))
        event = {
            "event_type":"activation_attestation","status":"ok","request_id":f"a{run}",
            "prompt_id":"p","model_ref":"approved","model_revision":"x",
            "fingerprint_sha256":"f","approved_activations_sha256":"a","thinking":"off",
            "measurements": {str(d):m for d,m in rows},
        }
        p.write_text(json.dumps(event)+"\n", encoding="utf-8")
        approved_logs.append(str(p))
    baseline = out / "baseline.json"
    build_baseline(approved_logs, baseline)

    suspect = out / "suspect.jsonl"
    measurements = {}
    for depth in [8, 16, 24, 32, 40, 48]:
        if depth < 32:
            rel = 0.0022
            cos = 0.999
        else:
            rel = 0.25 + depth*.02
            cos = 0.85
        measurements[str(depth)] = {
            "cosine_to_exact_approved_activation": cos,
            "relative_l2_to_exact_approved_activation": rel,
            "projection_delta_from_exact_approved": 0.0 if depth < 32 else 0.2,
            "projection_on_approved_direction": 1.0 if depth < 32 else 0.6,
        }
    suspect.write_text(json.dumps({
        "event_type":"activation_attestation","status":"ok","request_id":"s1",
        "prompt_id":"p","measurements":measurements
    })+"\n", encoding="utf-8")
    score_log(baseline, suspect, out/"score", z_threshold=5, min_consecutive=2)
    result = json.loads((out/"score"/"divergence_report.json").read_text())
    if result["first_material_divergence_depth"] != 32:
        raise RuntimeError(f"selftest expected depth 32, got {result}")
    print(json.dumps({"status":"PASS","first_divergence_depth":32}, indent=2))


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("build")
    p.add_argument("--log", action="append", required=True)
    p.add_argument("--out", required=True)
    p = sp.add_parser("score")
    p.add_argument("--baseline", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--z-threshold", type=float, default=5.0)
    p.add_argument("--min-consecutive", type=int, default=2)
    p = sp.add_parser("selftest")
    p.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "build":
        build_baseline(args.log, args.out)
    elif args.cmd == "score":
        score_log(args.baseline, args.log, args.out, args.z_threshold, args.min_consecutive)
    else:
        selftest(args.out)


if __name__ == "__main__":
    main()
