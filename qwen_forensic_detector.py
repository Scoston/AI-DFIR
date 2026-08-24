#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import math
import os
import re
import struct
from pathlib import Path
from typing import Dict, Tuple, Any

import numpy as np
import torch
from safetensors import safe_open


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def create_manifest(directory: Path) -> Dict[str, Any]:
    directory = directory.resolve()
    entries = []
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            st = p.stat()
            entries.append({
                "path": str(p.relative_to(directory)),
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "sha256": sha256_file(p),
            })
    return {
        "root": str(directory),
        "file_count": len(entries),
        "files": entries,
    }


def write_json(obj, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def parse_safetensors_header(path: Path) -> Dict[str, Any]:
    # Safetensors: first 8 bytes are little-endian unsigned header length,
    # followed by UTF-8 JSON. This reads metadata only, not tensor payloads.
    with path.open("rb") as f:
        raw = f.read(8)
        if len(raw) != 8:
            raise ValueError(f"{path}: too short for Safetensors header")
        (header_len,) = struct.unpack("<Q", raw)
        if header_len > 100 * 1024 * 1024:
            raise ValueError(f"{path}: unreasonable header length {header_len}")
        header = f.read(header_len)
    return json.loads(header.decode("utf-8"))


LAYER_RE = re.compile(r"(?:layers|layer)\.(\d+)\.")


def infer_layer(name: str):
    m = LAYER_RE.search(name)
    return int(m.group(1)) if m else None


def infer_component(name: str) -> str:
    n = name.lower()
    keys = [
        ("embed", "embedding"),
        ("lm_head", "lm_head"),
        ("vision", "vision"),
        ("mlp", "mlp"),
        ("ffn", "ffn"),
        ("linear_attn", "linear_attention"),
        ("linear_attention", "linear_attention"),
        ("self_attn", "attention"),
        ("attention", "attention"),
        ("norm", "norm"),
        ("mtp", "mtp"),
    ]
    for k, label in keys:
        if k in n:
            return label
    return "other"


def inventory(directory: Path):
    rows = []
    for sf in sorted(directory.rglob("*.safetensors")):
        try:
            header = parse_safetensors_header(sf)
        except Exception as e:
            rows.append({
                "tensor": "__HEADER_ERROR__",
                "shard": str(sf.relative_to(directory)),
                "dtype": "",
                "shape": "",
                "numel": "",
                "layer": "",
                "component": "",
                "error": str(e),
            })
            continue

        for name, meta in header.items():
            if name == "__metadata__":
                continue
            shape = meta.get("shape", [])
            numel = 1
            for d in shape:
                numel *= int(d)
            rows.append({
                "tensor": name,
                "shard": str(sf.relative_to(directory)),
                "dtype": meta.get("dtype", ""),
                "shape": json.dumps(shape),
                "numel": numel,
                "layer": infer_layer(name),
                "component": infer_component(name),
                "error": "",
            })
    return rows


def write_csv(rows, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        out.write_text("", encoding="utf-8")
        return
    fields = []
    seen = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                fields.append(k)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def compare_files(ref_manifest, sus_manifest):
    r = {x["path"]: x for x in ref_manifest["files"]}
    s = {x["path"]: x for x in sus_manifest["files"]}
    all_paths = sorted(set(r) | set(s))
    rows = []
    for p in all_paths:
        if p not in r:
            status = "suspect_only"
        elif p not in s:
            status = "reference_only"
        elif r[p]["sha256"] == s[p]["sha256"]:
            status = "identical"
        else:
            status = "different"
        rows.append({
            "path": p,
            "status": status,
            "reference": r.get(p),
            "suspect": s.get(p),
        })
    counts = {}
    for x in rows:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    return {"counts": counts, "files": rows}


def tensor_map(directory: Path) -> Dict[str, Tuple[Path, Dict[str, Any]]]:
    result = {}
    for sf in sorted(directory.rglob("*.safetensors")):
        header = parse_safetensors_header(sf)
        for name, meta in header.items():
            if name == "__metadata__":
                continue
            if name in result:
                raise ValueError(f"Duplicate tensor name {name} in {directory}")
            result[name] = (sf, meta)
    return result


def compare_one_tensor(ref_path: Path, sus_path: Path, name: str,
                       chunk_elements: int = 1_000_000,
                       abs_tol: float = 1e-6):
    with safe_open(str(ref_path), framework="pt", device="cpu") as rf, \
         safe_open(str(sus_path), framework="pt", device="cpu") as sf:
        rt = rf.get_tensor(name)
        st = sf.get_tensor(name)

        if tuple(rt.shape) != tuple(st.shape):
            return {"status": "shape_mismatch"}

        # Numerical comparison is meaningful only for floating tensors.
        if not (rt.dtype.is_floating_point and st.dtype.is_floating_point):
            same = torch.equal(rt, st)
            return {
                "status": "identical_nonfloat" if same else "different_nonfloat",
                "numel": rt.numel(),
            }

        rflat = rt.reshape(-1)
        sflat = st.reshape(-1)
        n = rflat.numel()

        delta_sq = 0.0
        ref_sq = 0.0
        abs_sum = 0.0
        max_abs = 0.0
        changed = 0

        for start in range(0, n, chunk_elements):
            end = min(start + chunk_elements, n)
            r = rflat[start:end].float()
            s = sflat[start:end].float()
            d = s - r
            ad = d.abs()

            delta_sq += float(torch.sum(d * d).item())
            ref_sq += float(torch.sum(r * r).item())
            abs_sum += float(torch.sum(ad).item())
            if ad.numel():
                max_abs = max(max_abs, float(torch.max(ad).item()))
            changed += int(torch.count_nonzero(ad > abs_tol).item())

        delta_fro = math.sqrt(delta_sq)
        ref_fro = math.sqrt(ref_sq)
        return {
            "status": "compared",
            "numel": n,
            "delta_fro": delta_fro,
            "reference_fro": ref_fro,
            "relative_fro_delta": delta_fro / (ref_fro + 1e-30),
            "mean_abs_delta": abs_sum / max(n, 1),
            "max_abs_delta": max_abs,
            "changed_fraction": changed / max(n, 1),
        }


def compare_tensors(reference: Path, suspect: Path, abs_tol=1e-6):
    rm = tensor_map(reference)
    sm = tensor_map(suspect)
    names = sorted(set(rm) | set(sm))
    rows = []

    for i, name in enumerate(names, 1):
        if name not in rm:
            rows.append({
                "tensor": name, "status": "suspect_only",
                "layer": infer_layer(name), "component": infer_component(name)
            })
            continue
        if name not in sm:
            rows.append({
                "tensor": name, "status": "reference_only",
                "layer": infer_layer(name), "component": infer_component(name)
            })
            continue

        rp, rmeta = rm[name]
        sp, smeta = sm[name]
        rshape = rmeta.get("shape", [])
        sshape = smeta.get("shape", [])
        row = {
            "tensor": name,
            "reference_shard": str(rp.relative_to(reference)),
            "suspect_shard": str(sp.relative_to(suspect)),
            "reference_dtype": rmeta.get("dtype", ""),
            "suspect_dtype": smeta.get("dtype", ""),
            "reference_shape": json.dumps(rshape),
            "suspect_shape": json.dumps(sshape),
            "layer": infer_layer(name),
            "component": infer_component(name),
        }

        if rshape != sshape:
            row["status"] = "shape_mismatch"
        elif rmeta.get("dtype") != smeta.get("dtype"):
            row["status"] = "dtype_mismatch"
        else:
            try:
                row.update(compare_one_tensor(rp, sp, name, abs_tol=abs_tol))
            except Exception as e:
                row["status"] = "error"
                row["error"] = repr(e)
        rows.append(row)

        if i % 50 == 0:
            print(f"[compare] processed {i}/{len(names)} tensors", flush=True)

    return rows


def deterministic_indices(n: int, k: int, seed: int):
    if n <= k:
        return torch.arange(n, dtype=torch.long)
    rng = np.random.default_rng(seed)
    idx = np.sort(rng.choice(n, size=k, replace=False))
    return torch.from_numpy(idx.astype(np.int64))


def low_rank_one(ref_path: Path, sus_path: Path, name: str,
                 max_dim=256, seed=1337):
    with safe_open(str(ref_path), framework="pt", device="cpu") as rf, \
         safe_open(str(sus_path), framework="pt", device="cpu") as sf:
        r = rf.get_tensor(name)
        s = sf.get_tensor(name)
        if r.ndim != 2 or s.ndim != 2 or tuple(r.shape) != tuple(s.shape):
            return None
        rows = deterministic_indices(r.shape[0], min(max_dim, r.shape[0]), seed)
        cols = deterministic_indices(r.shape[1], min(max_dim, r.shape[1]), seed + 1)

        # Sample before conversion to keep memory modest.
        rs = r.index_select(0, rows).index_select(1, cols).float()
        ss = s.index_select(0, rows).index_select(1, cols).float()
        d = ss - rs

        fro2 = float(torch.sum(d * d).item())
        if fro2 == 0.0:
            return {
                "sample_rows": len(rows), "sample_cols": len(cols),
                "sample_fro": 0.0, "top1_energy_ratio": 0.0,
                "top5_energy_ratio": 0.0, "effective_rank": 0.0,
            }

        sv = torch.linalg.svdvals(d)
        energy = sv * sv
        total = float(energy.sum().item())
        p = energy / (energy.sum() + 1e-30)
        entropy = float(-(p[p > 0] * torch.log(p[p > 0])).sum().item())
        eff_rank = math.exp(entropy)

        return {
            "sample_rows": len(rows),
            "sample_cols": len(cols),
            "sample_fro": math.sqrt(fro2),
            "top1_energy_ratio": float(energy[0].item() / total),
            "top5_energy_ratio": float(energy[:5].sum().item() / total),
            "effective_rank": eff_rank,
            "largest_singular_value": float(sv[0].item()),
        }


def low_rank_screen(reference: Path, suspect: Path, tensor_rows,
                    top=30, max_dim=256, seed=1337):
    rm = tensor_map(reference)
    sm = tensor_map(suspect)
    candidates = []
    for row in tensor_rows:
        if row.get("status") != "compared":
            continue
        try:
            rel = float(row.get("relative_fro_delta", 0.0))
        except Exception:
            continue
        name = row["tensor"]
        if rel <= 0 or name not in rm or name not in sm:
            continue
        shape = rm[name][1].get("shape", [])
        if len(shape) != 2:
            continue
        candidates.append((rel, name, row))
    candidates.sort(reverse=True, key=lambda x: x[0])
    candidates = candidates[:top]

    out = []
    for i, (rel, name, base) in enumerate(candidates, 1):
        rp, _ = rm[name]
        sp, _ = sm[name]
        try:
            metrics = low_rank_one(rp, sp, name, max_dim=max_dim, seed=seed)
            if metrics:
                out.append({
                    "tensor": name,
                    "layer": base.get("layer"),
                    "component": base.get("component"),
                    "relative_fro_delta": rel,
                    **metrics,
                })
        except Exception as e:
            out.append({
                "tensor": name,
                "layer": base.get("layer"),
                "component": base.get("component"),
                "relative_fro_delta": rel,
                "error": repr(e),
            })
        print(f"[low-rank] processed {i}/{len(candidates)}", flush=True)
    return out


def load_csv(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def make_report(file_cmp, tensor_rows, low_rows):
    fc = file_cmp.get("counts", {})
    tcomp = [r for r in tensor_rows if r.get("status") == "compared"]
    changed = []
    for r in tcomp:
        try:
            if float(r.get("relative_fro_delta", 0)) > 0:
                changed.append(r)
        except Exception:
            pass
    changed.sort(key=lambda r: float(r.get("relative_fro_delta", 0)), reverse=True)

    low_valid = []
    for r in low_rows:
        try:
            low_valid.append(r)
        except Exception:
            pass
    low_valid.sort(key=lambda r: float(r.get("top1_energy_ratio", 0) or 0), reverse=True)

    lines = []
    lines.append("# Qwen3.8 Model-Integrity Forensic Report")
    lines.append("")
    lines.append("## Executive triage")
    lines.append("")
    lines.append(f"- Identical files: **{fc.get('identical', 0)}**")
    lines.append(f"- Different files: **{fc.get('different', 0)}**")
    lines.append(f"- Suspect-only files: **{fc.get('suspect_only', 0)}**")
    lines.append(f"- Reference-only files: **{fc.get('reference_only', 0)}**")
    lines.append(f"- Numerically compared tensors: **{len(tcomp)}**")
    lines.append(f"- Tensors with non-zero numerical delta: **{len(changed)}**")
    lines.append("")
    lines.append("> A difference is an integrity finding, not by itself proof of abliteration. "
                 "Control for revision, quantization, conversion, re-sharding, adapters, and legitimate fine-tuning.")
    lines.append("")
    lines.append("## Largest tensor deltas")
    lines.append("")
    lines.append("| Tensor | Layer | Component | Relative Frobenius delta | Changed fraction |")
    lines.append("|---|---:|---|---:|---:|")
    for r in changed[:25]:
        lines.append(
            f"| `{r['tensor']}` | {r.get('layer','')} | {r.get('component','')} | "
            f"{float(r.get('relative_fro_delta',0)):.6g} | "
            f"{float(r.get('changed_fraction',0)):.6g} |"
        )
    if not changed:
        lines.append("| _No non-zero tensor deltas found_ | | | | |")

    lines.append("")
    lines.append("## Low-rank screening")
    lines.append("")
    lines.append("This is a deterministic sampled-submatrix SVD screening test. "
                 "High concentration in the first singular component across many relevant tensors "
                 "can be consistent with directional weight editing, but is not dispositive.")
    lines.append("")
    lines.append("| Tensor | Layer | Top-1 energy | Top-5 energy | Effective rank |")
    lines.append("|---|---:|---:|---:|---:|")
    for r in low_valid[:25]:
        if "error" in r:
            continue
        lines.append(
            f"| `{r['tensor']}` | {r.get('layer','')} | "
            f"{float(r.get('top1_energy_ratio',0)):.4f} | "
            f"{float(r.get('top5_energy_ratio',0)):.4f} | "
            f"{float(r.get('effective_rank',0)):.2f} |"
        )
    if not low_valid:
        lines.append("| _No low-rank results_ | | | | |")

    lines.append("")
    lines.append("## Interpretation checklist")
    lines.append("")
    lines.append("- [ ] Verify the suspect and reference derive from the **same approved commit/revision**.")
    lines.append("- [ ] Verify dtype/quantization/conversion pipelines are equivalent.")
    lines.append("- [ ] Review suspect-only adapter/PEFT/LoRA artifacts.")
    lines.append("- [ ] Compare `config.json`, tokenizer configuration, chat template, and generation config.")
    lines.append("- [ ] Review serving process command line, environment, loaded files, container image, and source.")
    lines.append("- [ ] Search for runtime hooks/control vectors/activation steering.")
    lines.append("- [ ] Run matched behavioral probes against known-good and suspect deployments.")
    lines.append("- [ ] Build a timeline tying deployment changes to the first observed behavioral anomaly.")
    lines.append("")
    lines.append("## Evidentiary conclusion guidance")
    lines.append("")
    lines.append("Do not label the checkpoint 'abliterated' from a refusal-rate change or a hash mismatch alone. "
                 "A strong attribution should correlate artifact provenance, tensor geometry/localization, "
                 "runtime evidence, and behavior.")
    lines.append("")
    return "\n".join(lines) + "\n"


def cmd_manifest(args):
    m = create_manifest(Path(args.directory))
    write_json(m, Path(args.out))
    print(f"Wrote {args.out}")


def cmd_inventory(args):
    rows = inventory(Path(args.directory))
    write_csv(rows, Path(args.out))
    print(f"Wrote {args.out}")


def cmd_full(args):
    ref = Path(args.reference).resolve()
    sus = Path(args.suspect).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    print("[1/6] hashing reference")
    rm = create_manifest(ref)
    write_json(rm, out / "reference_manifest.json")

    print("[2/6] hashing suspect")
    sm = create_manifest(sus)
    write_json(sm, out / "suspect_manifest.json")

    print("[3/6] reading Safetensors headers")
    ri = inventory(ref)
    si = inventory(sus)
    write_csv(ri, out / "reference_inventory.csv")
    write_csv(si, out / "suspect_inventory.csv")
    fc = compare_files(rm, sm)
    write_json(fc, out / "file_comparison.json")

    print("[4/6] numerical tensor comparison")
    tr = compare_tensors(ref, sus, abs_tol=args.abs_tol)
    write_csv(tr, out / "tensor_metrics.csv")

    print("[5/6] low-rank screening")
    lr = low_rank_screen(ref, sus, tr, top=args.top, max_dim=args.sample_dim, seed=args.seed)
    write_csv(lr, out / "low_rank_screen.csv")

    print("[6/6] report")
    report = make_report(fc, tr, lr)
    (out / "report.md").write_text(report, encoding="utf-8")
    print(f"Analysis complete: {out}")
    print(f"Report: {out / 'report.md'}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Qwen3.8 model-integrity forensic detector (non-destructive static analysis)"
    )
    sp = p.add_subparsers(dest="cmd", required=True)

    a = sp.add_parser("manifest", help="Create SHA-256 evidence manifest")
    a.add_argument("directory")
    a.add_argument("--out", required=True)
    a.set_defaults(func=cmd_manifest)

    a = sp.add_parser("inventory", help="Inventory Safetensors headers without loading the model")
    a.add_argument("directory")
    a.add_argument("--out", required=True)
    a.set_defaults(func=cmd_inventory)

    a = sp.add_parser("full", help="Run full reference-vs-suspect static analysis")
    a.add_argument("--reference", required=True)
    a.add_argument("--suspect", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--abs-tol", type=float, default=1e-6)
    a.add_argument("--top", type=int, default=30,
                   help="number of most-changed 2-D tensors to low-rank screen")
    a.add_argument("--sample-dim", type=int, default=256,
                   help="maximum rows/columns in deterministic SVD submatrix")
    a.add_argument("--seed", type=int, default=1337)
    a.set_defaults(func=cmd_full)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
