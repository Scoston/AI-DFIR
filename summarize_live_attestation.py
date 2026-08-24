#!/usr/bin/env python3
"""Summarize v0.3 activation-attestation JSONL by residual depth."""
import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


def pct(values, q):
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - pos) + xs[hi] * (pos - lo)


def fnum(v):
    return "" if v is None else f"{v:.6f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    events = []
    with open(args.log, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("event_type") == "activation_attestation" and e.get("status") == "ok":
                events.append(e)

    by_depth = defaultdict(lambda: defaultdict(list))
    for e in events:
        for depth, m in e.get("measurements", {}).items():
            for k, v in m.items():
                if isinstance(v, (int, float)):
                    by_depth[int(depth)][k].append(float(v))

    rows = []
    for depth in sorted(by_depth):
        d = by_depth[depth]
        exact_cos = d.get("cosine_to_exact_approved_activation", [])
        rel_l2 = d.get("relative_l2_to_exact_approved_activation", [])
        proj_delta = d.get("projection_delta_from_exact_approved", [])
        projection = d.get("projection_on_approved_direction", [])
        rows.append({
            "depth": depth,
            "samples": max([len(v) for v in d.values()] or [0]),
            "exact_cosine_median": statistics.median(exact_cos) if exact_cos else None,
            "exact_cosine_p05": pct(exact_cos, 0.05),
            "exact_cosine_min": min(exact_cos) if exact_cos else None,
            "relative_l2_median": statistics.median(rel_l2) if rel_l2 else None,
            "relative_l2_p95": pct(rel_l2, 0.95),
            "relative_l2_max": max(rel_l2) if rel_l2 else None,
            "abs_projection_delta_median": (
                statistics.median([abs(x) for x in proj_delta]) if proj_delta else None
            ),
            "abs_projection_delta_p95": (
                pct([abs(x) for x in proj_delta], 0.95) if proj_delta else None
            ),
            "approved_direction_projection_median": (
                statistics.median(projection) if projection else None
            ),
        })

    # Rank by direct exact-reference divergence when available.
    ranked = sorted(
        rows,
        key=lambda r: (
            -(r["relative_l2_p95"] if r["relative_l2_p95"] is not None else -1),
            (r["exact_cosine_p05"] if r["exact_cosine_p05"] is not None else 2),
        )
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    fields = list(rows[0].keys()) if rows else ["depth", "samples"]
    with (out / "depth_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    report = []
    report.append("# Live Activation Attestation Summary")
    report.append("")
    report.append(f"- Successful attestation events: **{len(events)}**")
    report.append(f"- Residual depths observed: **{len(rows)}**")
    report.append("")
    report.append("## Highest observed divergence")
    report.append("")
    report.append("| Depth | Samples | Exact cosine p05 | Relative L2 p95 | |Projection Δ| p95 |")
    report.append("|---:|---:|---:|---:|---:|")
    for r in ranked[:15]:
        report.append(
            f"| {r['depth']} | {r['samples']} | "
            f"{fnum(r['exact_cosine_p05'])} | "
            f"{fnum(r['relative_l2_p95'])} | "
            f"{fnum(r['abs_projection_delta_p95'])} |"
        )
    if not rows:
        report.append("| _No successful activation-attestation measurements found_ | | | | |")

    report.append("")
    report.append("## Interpretation")
    report.append("")
    report.append(
        "This report ranks divergence; it does not apply a universal tampering threshold. "
        "Establish local thresholds from approved deployments using the same checkpoint, "
        "precision/quantization, tokenizer/chat template, thinking mode, serving stack, "
        "probe set, and selected depths."
    )
    report.append("")
    report.append(
        "For attribution, correlate activation divergence with checkpoint/tensor analysis, "
        "runtime hook/adapter evidence, process provenance, and the incident timeline."
    )
    (out / "live_attestation_summary.md").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )

    print(f"Wrote {out / 'depth_summary.csv'}")
    print(f"Wrote {out / 'live_attestation_summary.md'}")


if __name__ == "__main__":
    main()
