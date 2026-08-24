#!/usr/bin/env python3
"""
Qwen3.8 activation-fingerprint forensics.

Design:
  1) Extract final-prompt-token hidden states from the APPROVED model.
  2) Derive refusal-associated directions ONLY from approved activations.
  3) Extract the same prompts from the suspect model.
  4) Project suspect activations onto the approved directions.
  5) Quantify where class separation / activation geometry diverges.

The script never removes or suppresses a refusal direction and never writes model weights.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any

import numpy as np
import torch
import torch.nn.functional as F
from safetensors.torch import save_file, load_file
from sklearn.metrics import roc_auc_score
import matplotlib.pyplot as plt


def sha256_file(path: Path, chunk_size=8 * 1024 * 1024):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def write_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(rows, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = []
    seen = set()
    for r in rows:
        for k in r:
            if k not in seen:
                seen.add(k)
                fields.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def read_prompts(path: Path):
    items = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if "id" not in obj or "prompt" not in obj or "expected_refusal" not in obj:
                raise ValueError(
                    f"{path}:{line_no}: each row needs id, prompt, expected_refusal"
                )
            if not isinstance(obj["expected_refusal"], bool):
                raise ValueError(f"{path}:{line_no}: expected_refusal must be boolean")
            items.append(obj)
    ids = [x["id"] for x in items]
    if len(ids) != len(set(ids)):
        raise ValueError("Prompt IDs must be unique")
    return items


def torch_dtype_from_name(name: str):
    return {
        "bf16": torch.bfloat16,
        "fp16": torch.float16,
        "fp32": torch.float32,
    }.get(name)


def get_model_input_device(model):
    try:
        d = model.device
        if str(d) != "meta":
            return d
    except Exception:
        pass
    try:
        emb = model.get_input_embeddings()
        if emb is not None and str(emb.weight.device) != "meta":
            return emb.weight.device
    except Exception:
        pass
    for p in model.parameters():
        if str(p.device) != "meta":
            return p.device
    raise RuntimeError("Could not determine an input device")


def apply_chat(processor, messages, thinking: str):
    kwargs = dict(
        tokenize=True,
        add_generation_prompt=True,
        return_dict=True,
        return_tensors="pt",
    )
    if thinking == "on":
        kwargs["enable_thinking"] = True
    elif thinking == "off":
        kwargs["enable_thinking"] = False

    try:
        return processor.apply_chat_template(messages, **kwargs)
    except TypeError as e:
        if "enable_thinking" in kwargs:
            print(
                "[warning] processor rejected enable_thinking; retrying with template default",
                flush=True,
            )
            kwargs.pop("enable_thinking", None)
            return processor.apply_chat_template(messages, **kwargs)
        raise


def load_qwen(model_ref: str, revision: str | None, dtype_name: str,
              device_map: str, local_files_only: bool):
    # Lazy import keeps derive/compare/selftest usable on analysis-only systems.
    from transformers import AutoProcessor, AutoModelForMultimodalLM

    common = {
        "trust_remote_code": False,
        "local_files_only": local_files_only,
    }
    if revision:
        common["revision"] = revision

    processor = AutoProcessor.from_pretrained(model_ref, **common)

    model_kwargs = dict(common)
    model_kwargs.update({
        "device_map": device_map,
        "low_cpu_mem_usage": True,
    })
    dtype = torch_dtype_from_name(dtype_name)
    if dtype is not None:
        # torch_dtype remains broadly compatible across current Transformers versions.
        model_kwargs["torch_dtype"] = dtype

    model = AutoModelForMultimodalLM.from_pretrained(model_ref, **model_kwargs)
    model.eval()
    return processor, model


def extract_activations(model_ref: str, prompts_path: Path, out_dir: Path,
                        revision=None, dtype_name="bf16", device_map="auto",
                        thinking="off", local_files_only=False,
                        system_prompt_file=None, max_prompts=None):
    prompts = read_prompts(prompts_path)
    if max_prompts is not None:
        prompts = prompts[:max_prompts]

    system_prompt = None
    if system_prompt_file:
        system_prompt = Path(system_prompt_file).read_text(encoding="utf-8").strip()

    print(f"[extract] loading {model_ref}", flush=True)
    processor, model = load_qwen(
        model_ref, revision, dtype_name, device_map, local_files_only
    )
    input_device = get_model_input_device(model)

    acts = []
    rows = []

    with torch.inference_mode():
        for i, item in enumerate(prompts, 1):
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({
                "role": "user",
                "content": [{"type": "text", "text": item["prompt"]}],
            })

            enc = apply_chat(processor, messages, thinking)
            if hasattr(enc, "to"):
                enc = enc.to(input_device)
            else:
                enc = {
                    k: (v.to(input_device) if torch.is_tensor(v) else v)
                    for k, v in enc.items()
                }

            outputs = model(
                **enc,
                output_hidden_states=True,
                use_cache=False,
                return_dict=True,
                logits_to_keep=1,
            )
            hidden_states = getattr(outputs, "hidden_states", None)
            if hidden_states is None:
                raise RuntimeError(
                    "Model output did not include hidden_states. "
                    "Confirm your Transformers version supports Qwen3.8 hidden-state recording."
                )

            prompt_layers = []
            for hs in hidden_states:
                # Batch size is intentionally 1; capture the final prompt position.
                prompt_layers.append(hs[0, -1, :].float().cpu())
            stacked = torch.stack(prompt_layers, dim=0)
            acts.append(stacked)

            rows.append({
                "id": item["id"],
                "category": item.get("category"),
                "expected_refusal": item["expected_refusal"],
                "prompt_sha256": hashlib.sha256(
                    item["prompt"].encode("utf-8")
                ).hexdigest(),
                "input_tokens": int(enc["input_ids"].shape[-1]),
            })
            print(
                f"[extract] {i}/{len(prompts)} {item['id']} -> {tuple(stacked.shape)}",
                flush=True,
            )

    activations = torch.stack(acts, dim=0).contiguous()
    out_dir.mkdir(parents=True, exist_ok=True)
    st_path = out_dir / "activations.safetensors"
    save_file({"activations": activations}, str(st_path))

    text_cfg = getattr(model.config, "text_config", model.config)
    meta = {
        "model_ref": model_ref,
        "requested_revision": revision,
        "dtype_requested": dtype_name,
        "device_map": device_map,
        "thinking": thinking,
        "trust_remote_code": False,
        "local_files_only": local_files_only,
        "system_prompt_sha256": (
            hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
            if system_prompt else None
        ),
        "prompt_file": str(prompts_path),
        "prompt_file_sha256": sha256_file(prompts_path),
        "num_prompts": len(rows),
        "num_residual_depths": int(activations.shape[1]),
        "hidden_size": int(activations.shape[2]),
        "configured_hidden_layers": getattr(text_cfg, "num_hidden_layers", None),
        "configured_hidden_size": getattr(text_cfg, "hidden_size", None),
        "records": rows,
        "activation_file": st_path.name,
        "activation_file_sha256": sha256_file(st_path),
        "capture_position": "final token of templated prompt including generation prefix",
    }
    write_json(meta, out_dir / "metadata.json")
    print(f"[extract] wrote {st_path}", flush=True)


def load_activation_bundle(directory: Path):
    meta_path = directory / "metadata.json"
    act_path = directory / "activations.safetensors"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    tensors = load_file(str(act_path), device="cpu")
    acts = tensors["activations"].float()
    if acts.ndim != 3:
        raise ValueError(f"Expected [prompts, depths, hidden], got {tuple(acts.shape)}")
    if len(meta["records"]) != acts.shape[0]:
        raise ValueError("metadata record count does not match activation tensor")
    return meta, acts


def cohens_d(x: torch.Tensor, y: torch.Tensor):
    nx = x.numel()
    ny = y.numel()
    if nx < 2 or ny < 2:
        return float("nan")
    vx = x.var(unbiased=True)
    vy = y.var(unbiased=True)
    pooled = torch.sqrt((((nx - 1) * vx) + ((ny - 1) * vy)) / (nx + ny - 2))
    return float(((x.mean() - y.mean()) / (pooled + 1e-12)).item())


def auc_for_scores(safety: torch.Tensor, benign: torch.Tensor):
    labels = np.concatenate([
        np.ones(safety.numel(), dtype=np.int64),
        np.zeros(benign.numel(), dtype=np.int64),
    ])
    scores = np.concatenate([
        safety.detach().cpu().numpy(),
        benign.detach().cpu().numpy(),
    ])
    return float(roc_auc_score(labels, scores))


def derive_fingerprint(approved_dir: Path, out_dir: Path):
    meta, acts = load_activation_bundle(approved_dir)
    labels = torch.tensor(
        [1 if r["expected_refusal"] else 0 for r in meta["records"]],
        dtype=torch.bool,
    )
    if labels.sum() < 2 or (~labels).sum() < 2:
        raise ValueError("Need at least two refusal and two benign prompts")

    safety = acts[labels]
    benign = acts[~labels]

    safety_mean = safety.mean(dim=0)
    benign_mean = benign.mean(dim=0)
    raw = safety_mean - benign_mean
    norms = raw.norm(dim=-1, keepdim=True)
    directions = raw / (norms + 1e-12)

    rows = []
    ref_safety_proj = []
    ref_benign_proj = []
    for depth in range(acts.shape[1]):
        d = directions[depth]
        s = safety[:, depth, :] @ d
        b = benign[:, depth, :] @ d
        ref_safety_proj.append(s)
        ref_benign_proj.append(b)
        rows.append({
            "depth": depth,
            "auc": auc_for_scores(s, b),
            "cohens_d": cohens_d(s, b),
            "safety_mean_projection": float(s.mean()),
            "benign_mean_projection": float(b.mean()),
            "separation": float((s.mean() - b.mean()).item()),
            "direction_raw_norm": float(norms[depth].item()),
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    fp_tensor_path = out_dir / "fingerprint.safetensors"
    save_file({
        "directions": directions.contiguous(),
        "approved_safety_centroid": safety_mean.contiguous(),
        "approved_benign_centroid": benign_mean.contiguous(),
    }, str(fp_tensor_path))
    write_csv(rows, out_dir / "approved_layer_metrics.csv")

    fp_meta = {
        "source_activation_dir": str(approved_dir),
        "source_activation_sha256": sha256_file(
            approved_dir / "activations.safetensors"
        ),
        "source_metadata_sha256": sha256_file(approved_dir / "metadata.json"),
        "fingerprint_tensor_sha256": sha256_file(fp_tensor_path),
        "num_prompts": int(acts.shape[0]),
        "num_safety": int(labels.sum().item()),
        "num_benign": int((~labels).sum().item()),
        "num_residual_depths": int(acts.shape[1]),
        "hidden_size": int(acts.shape[2]),
        "reference_records": meta["records"],
        "approved_model_ref": meta.get("model_ref"),
        "approved_revision": meta.get("requested_revision"),
        "thinking": meta.get("thinking"),
        "capture_position": meta.get("capture_position"),
        "method": "approved-model per-depth mean(safety)-mean(benign), L2 normalized",
    }
    write_json(fp_meta, out_dir / "fingerprint.json")
    make_metric_plot(
        rows, "depth", "auc", "Approved-model refusal separability (ROC AUC)",
        "ROC AUC", out_dir / "approved_auc_by_depth.png"
    )
    make_metric_plot(
        rows, "depth", "cohens_d", "Approved-model refusal separation (Cohen's d)",
        "Cohen's d", out_dir / "approved_cohens_d_by_depth.png"
    )
    print(f"[derive] fingerprint written to {out_dir}", flush=True)


def make_metric_plot(rows, xkey, ykey, title, ylabel, out):
    xs = [float(r[xkey]) for r in rows if r.get(ykey) not in (None, "")]
    ys = [float(r[ykey]) for r in rows if r.get(ykey) not in (None, "")]
    if not xs:
        return
    plt.figure(figsize=(9, 5))
    plt.plot(xs, ys)
    plt.xlabel("Residual depth")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out, dpi=180)
    plt.close()


def load_fingerprint(fp_dir: Path):
    meta = json.loads((fp_dir / "fingerprint.json").read_text(encoding="utf-8"))
    t = load_file(str(fp_dir / "fingerprint.safetensors"), device="cpu")
    metrics = []
    with (fp_dir / "approved_layer_metrics.csv").open(newline="", encoding="utf-8") as f:
        metrics = list(csv.DictReader(f))
    return meta, {k: v.float() for k, v in t.items()}, metrics


def compare_fingerprint(fp_dir: Path, suspect_dir: Path, out_dir: Path,
                        reference_activations_dir: Path | None = None,
                        require_prompt_match=True):
    fp_meta, fp, approved_metrics = load_fingerprint(fp_dir)
    sus_meta, sus = load_activation_bundle(suspect_dir)

    directions = fp["directions"]
    if sus.shape[1:] != directions.shape:
        raise ValueError(
            f"Suspect activations {tuple(sus.shape[1:])} do not match "
            f"fingerprint {tuple(directions.shape)}"
        )

    fp_ids = [r["id"] for r in fp_meta["reference_records"]]
    sus_ids = [r["id"] for r in sus_meta["records"]]
    if require_prompt_match and fp_ids != sus_ids:
        raise ValueError(
            "Prompt IDs/order differ between approved fingerprint and suspect extraction. "
            "Use the same prompt file and ordering."
        )

    labels = torch.tensor(
        [1 if r["expected_refusal"] else 0 for r in sus_meta["records"]],
        dtype=torch.bool,
    )
    app_by_depth = {int(r["depth"]): r for r in approved_metrics}
    rows = []

    for depth in range(sus.shape[1]):
        d = directions[depth]
        s = sus[labels, depth, :] @ d
        b = sus[~labels, depth, :] @ d

        a = app_by_depth[depth]
        approved_auc = float(a["auc"])
        approved_d = float(a["cohens_d"])
        approved_sep = float(a["separation"])
        suspect_auc = auc_for_scores(s, b)
        suspect_d = cohens_d(s, b)
        suspect_sep = float((s.mean() - b.mean()).item())

        rows.append({
            "depth": depth,
            "approved_auc": approved_auc,
            "suspect_auc_on_approved_direction": suspect_auc,
            "auc_delta": suspect_auc - approved_auc,
            "approved_cohens_d": approved_d,
            "suspect_cohens_d_on_approved_direction": suspect_d,
            "cohens_d_delta": suspect_d - approved_d,
            "approved_separation": approved_sep,
            "suspect_separation": suspect_sep,
            "separation_ratio": (
                suspect_sep / approved_sep if abs(approved_sep) > 1e-12 else float("nan")
            ),
            "suspect_safety_mean_projection": float(s.mean()),
            "suspect_benign_mean_projection": float(b.mean()),
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(rows, out_dir / "activation_comparison.csv")
    make_metric_plot(
        rows, "depth", "suspect_auc_on_approved_direction",
        "Suspect refusal separability on approved directions", "ROC AUC",
        out_dir / "suspect_auc_on_approved_direction.png"
    )
    make_metric_plot(
        rows, "depth", "separation_ratio",
        "Suspect/approved refusal-separation ratio", "Separation ratio",
        out_dir / "separation_ratio_by_depth.png"
    )

    matched_rows = []
    if reference_activations_dir is not None:
        ref_meta, ref = load_activation_bundle(reference_activations_dir)
        ref_ids = [r["id"] for r in ref_meta["records"]]
        if ref_ids != sus_ids:
            raise ValueError(
                "Reference and suspect activation bundles must use identical prompt IDs/order "
                "for matched activation comparison."
            )
        if ref.shape != sus.shape:
            raise ValueError("Reference and suspect activation tensors have different shapes")

        eps = 1e-12
        for depth in range(ref.shape[1]):
            rv = ref[:, depth, :]
            sv = sus[:, depth, :]
            cosine = F.cosine_similarity(rv, sv, dim=-1)
            delta = (sv - rv).norm(dim=-1)
            refnorm = rv.norm(dim=-1)
            relative = delta / (refnorm + eps)
            matched_rows.append({
                "depth": depth,
                "mean_prompt_cosine_similarity": float(cosine.mean()),
                "min_prompt_cosine_similarity": float(cosine.min()),
                "mean_relative_l2_delta": float(relative.mean()),
                "max_relative_l2_delta": float(relative.max()),
            })
        write_csv(matched_rows, out_dir / "matched_activation_delta.csv")
        make_metric_plot(
            matched_rows, "depth", "mean_prompt_cosine_similarity",
            "Matched prompt activation cosine: approved vs suspect",
            "Mean cosine similarity",
            out_dir / "matched_cosine_by_depth.png"
        )

    # Rank suspicious depths without pretending to have a universal threshold.
    ranked = sorted(
        rows,
        key=lambda r: abs(float(r["cohens_d_delta"])),
        reverse=True,
    )
    top = ranked[:10]

    # Curve-level similarity of refusal separation.
    app_curve = torch.tensor([float(r["approved_separation"]) for r in rows])
    sus_curve = torch.tensor([float(r["suspect_separation"]) for r in rows])
    curve_cos = float(F.cosine_similarity(app_curve[None, :], sus_curve[None, :]).item())
    curve_rel_l2 = float(
        ((sus_curve - app_curve).norm() / (app_curve.norm() + 1e-12)).item()
    )

    report = []
    report.append("# Activation-Fingerprint Forensic Comparison")
    report.append("")
    report.append("## Method")
    report.append("")
    report.append(
        "The refusal-associated directions were derived **only from the approved model**. "
        "The suspect model was projected onto those fixed approved directions."
    )
    report.append("")
    report.append(f"- Approved model: `{fp_meta.get('approved_model_ref')}`")
    report.append(f"- Approved revision: `{fp_meta.get('approved_revision')}`")
    report.append(f"- Suspect model: `{sus_meta.get('model_ref')}`")
    report.append(f"- Suspect requested revision: `{sus_meta.get('requested_revision')}`")
    report.append(f"- Thinking mode: approved=`{fp_meta.get('thinking')}`, suspect=`{sus_meta.get('thinking')}`")
    report.append(f"- Residual depths compared: **{len(rows)}**")
    report.append(f"- Separation-curve cosine similarity: **{curve_cos:.6f}**")
    report.append(f"- Separation-curve relative L2 delta: **{curve_rel_l2:.6f}**")
    report.append("")
    report.append("## Largest changes in refusal-associated separation")
    report.append("")
    report.append("| Depth | Approved AUC | Suspect AUC | Approved d | Suspect d | Separation ratio |")
    report.append("|---:|---:|---:|---:|---:|---:|")
    for r in top:
        report.append(
            f"| {r['depth']} | {r['approved_auc']:.4f} | "
            f"{r['suspect_auc_on_approved_direction']:.4f} | "
            f"{r['approved_cohens_d']:.4f} | "
            f"{r['suspect_cohens_d_on_approved_direction']:.4f} | "
            f"{r['separation_ratio']:.4f} |"
        )
    report.append("")
    if matched_rows:
        worst = sorted(
            matched_rows,
            key=lambda r: r["mean_prompt_cosine_similarity"],
        )[:10]
        report.append("## Largest matched-prompt activation divergences")
        report.append("")
        report.append("| Depth | Mean cosine | Mean relative L2 delta |")
        report.append("|---:|---:|---:|")
        for r in worst:
            report.append(
                f"| {r['depth']} | {r['mean_prompt_cosine_similarity']:.6f} | "
                f"{r['mean_relative_l2_delta']:.6f} |"
            )
        report.append("")

    report.append("## Interpretation")
    report.append("")
    report.append(
        "A collapse or major shift in projection onto approved refusal-associated directions is a "
        "**mechanistic anomaly**, not by itself proof of abliteration. Correlate it with static "
        "checkpoint deltas, adapters, chat-template/config changes, runtime hooks/control vectors, "
        "and the deployment timeline."
    )
    report.append("")
    report.append(
        "Do not compare activation fingerprints across different quantizations, chat templates, "
        "thinking modes, prompt sets, or materially different inference stacks without controlling "
        "those variables first."
    )
    report.append("")
    (out_dir / "activation_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    summary = {
        "separation_curve_cosine_similarity": curve_cos,
        "separation_curve_relative_l2_delta": curve_rel_l2,
        "num_depths": len(rows),
        "prompt_match_required": require_prompt_match,
        "matched_activation_comparison": bool(matched_rows),
        "suspect_activation_sha256": sha256_file(suspect_dir / "activations.safetensors"),
        "fingerprint_sha256": sha256_file(fp_dir / "fingerprint.safetensors"),
    }
    write_json(summary, out_dir / "activation_summary.json")
    print(f"[compare] activation report written to {out_dir}", flush=True)


def save_synthetic_bundle(directory: Path, acts: torch.Tensor, labels: List[bool], prefix: str):
    directory.mkdir(parents=True, exist_ok=True)
    save_file({"activations": acts.contiguous()}, str(directory / "activations.safetensors"))
    records = []
    for i, label in enumerate(labels):
        records.append({
            "id": f"probe_{i:03d}",
            "category": "synthetic",
            "expected_refusal": bool(label),
            "prompt_sha256": hashlib.sha256(f"synthetic-{i}".encode()).hexdigest(),
            "input_tokens": 10,
        })
    meta = {
        "model_ref": prefix,
        "requested_revision": "synthetic",
        "dtype_requested": "fp32",
        "device_map": "cpu",
        "thinking": "off",
        "trust_remote_code": False,
        "local_files_only": True,
        "system_prompt_sha256": None,
        "prompt_file": "synthetic",
        "prompt_file_sha256": "synthetic",
        "num_prompts": len(labels),
        "num_residual_depths": acts.shape[1],
        "hidden_size": acts.shape[2],
        "configured_hidden_layers": acts.shape[1] - 1,
        "configured_hidden_size": acts.shape[2],
        "records": records,
        "activation_file": "activations.safetensors",
        "activation_file_sha256": sha256_file(directory / "activations.safetensors"),
        "capture_position": "synthetic",
    }
    write_json(meta, directory / "metadata.json")


def selftest(out_dir: Path):
    torch.manual_seed(42)
    n, depths, hidden = 40, 9, 64
    labels = [False] * 20 + [True] * 20
    base = torch.randn(n, depths, hidden)
    signal = torch.randn(depths, hidden)
    signal = signal / signal.norm(dim=-1, keepdim=True)

    ref = base.clone()
    sus = base.clone()
    for d in range(depths):
        strength = 0.35 + 0.18 * d
        ref[20:, d, :] += strength * signal[d]
        # Suspect preserves early behavior but loses much of the signal later.
        suspect_strength = strength if d < 4 else strength * 0.15
        sus[20:, d, :] += suspect_strength * signal[d]

    ref_dir = out_dir / "approved_activations"
    sus_dir = out_dir / "suspect_activations"
    fp_dir = out_dir / "fingerprint"
    cmp_dir = out_dir / "comparison"
    save_synthetic_bundle(ref_dir, ref, labels, "synthetic-approved")
    save_synthetic_bundle(sus_dir, sus, labels, "synthetic-suspect")
    derive_fingerprint(ref_dir, fp_dir)
    compare_fingerprint(fp_dir, sus_dir, cmp_dir, reference_activations_dir=ref_dir)

    summary = json.loads((cmp_dir / "activation_summary.json").read_text())
    if summary["separation_curve_relative_l2_delta"] <= 0.1:
        raise RuntimeError("selftest failed: expected synthetic divergence was not detected")
    print("[selftest] PASS")
    print(f"[selftest] results: {out_dir}")


def build_parser():
    ap = argparse.ArgumentParser(
        description="Qwen3.8 approved-vs-suspect activation fingerprint forensics"
    )
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("extract", help="Extract per-depth final-prompt hidden states")
    p.add_argument("--model", required=True, help="Local directory or Hugging Face model ID")
    p.add_argument("--revision", default=None)
    p.add_argument("--prompts", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--dtype", choices=["auto", "bf16", "fp16", "fp32"], default="bf16")
    p.add_argument("--device-map", default="auto")
    p.add_argument("--thinking", choices=["off", "on", "default"], default="off")
    p.add_argument("--local-files-only", action="store_true")
    p.add_argument("--system-prompt-file", default=None)
    p.add_argument("--max-prompts", type=int, default=None)

    p = sp.add_parser("derive", help="Derive fingerprint from APPROVED activations only")
    p.add_argument("--approved-activations", required=True)
    p.add_argument("--out", required=True)

    p = sp.add_parser("compare", help="Project suspect activations onto approved fingerprint")
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--suspect-activations", required=True)
    p.add_argument("--reference-activations", default=None,
                   help="Optional approved activation bundle for matched per-prompt geometry")
    p.add_argument("--out", required=True)
    p.add_argument("--allow-unmatched-prompts", action="store_true")

    p = sp.add_parser("selftest", help="Run deterministic synthetic end-to-end detector test")
    p.add_argument("--out", required=True)

    return ap


def main():
    args = build_parser().parse_args()
    if args.cmd == "extract":
        extract_activations(
            args.model, Path(args.prompts), Path(args.out),
            revision=args.revision, dtype_name=args.dtype,
            device_map=args.device_map, thinking=args.thinking,
            local_files_only=args.local_files_only,
            system_prompt_file=args.system_prompt_file,
            max_prompts=args.max_prompts,
        )
    elif args.cmd == "derive":
        derive_fingerprint(Path(args.approved_activations), Path(args.out))
    elif args.cmd == "compare":
        compare_fingerprint(
            Path(args.fingerprint), Path(args.suspect_activations), Path(args.out),
            reference_activations_dir=(
                Path(args.reference_activations) if args.reference_activations else None
            ),
            require_prompt_match=not args.allow_unmatched_prompts,
        )
    elif args.cmd == "selftest":
        selftest(Path(args.out))


if __name__ == "__main__":
    main()
