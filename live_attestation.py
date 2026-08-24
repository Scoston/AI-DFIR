#!/usr/bin/env python3
"""
Passive live activation attestation for Qwen3.8-class Transformers models.

Security properties:
- Observation-only forward hooks. Hooks always return None.
- No weight edits, steering, projection removal, or activation modification.
- Refusal directions are loaded from an approved fingerprint.
- Optional exact-prompt reference activations are loaded from the approved model.
- Each event is SHA-256 hash chained; optional HMAC-SHA256 protects the chain
  when the key is held outside the inference host.
- Probe mode generates at most one token by default and discards it.

Forensic caveat:
A local hash chain detects accidental/casual modification but can be recomputed
by an attacker who controls the host. For stronger evidence, use HMAC with a key
not stored on the inference host and export chain heads to WORM/SIEM storage.
"""
from __future__ import annotations

import argparse
import contextvars
import csv
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch
import torch.nn.functional as F
from safetensors.torch import load_file
from model_adapters import choose_adapter


SCHEMA = "qwen-live-attestation/v0.3"


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size=8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def read_boot_id():
    p = Path("/proc/sys/kernel/random/boot_id")
    try:
        return p.read_text(encoding="utf-8").strip()
    except Exception:
        return None


def process_cmdline_sha256():
    try:
        b = Path("/proc/self/cmdline").read_bytes()
        return sha256_bytes(b)
    except Exception:
        return None


def package_versions():
    result = {}
    for name in ["torch", "transformers", "safetensors", "accelerate", "numpy"]:
        try:
            result[name] = importlib.metadata.version(name)
        except Exception:
            result[name] = None
    return result


def load_hmac_key_from_env() -> Optional[bytes]:
    raw = os.getenv("QWEN_ATTESTATION_HMAC_KEY_HEX")
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError as e:
        raise RuntimeError(
            "QWEN_ATTESTATION_HMAC_KEY_HEX must contain a hex-encoded secret"
        ) from e
    if len(key) < 32:
        raise RuntimeError("Attestation HMAC key must be at least 32 bytes")
    return key


class ChainLogger:
    def __init__(self, path: Path, hmac_key: Optional[bytes] = None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.hmac_key = hmac_key
        self.prev_hash = "0" * 64
        self.count = 0
        if self.path.exists() and self.path.stat().st_size:
            self._resume_existing()

    def _resume_existing(self):
        ok, info = verify_log(self.path, self.hmac_key, require_hmac=False)
        if not ok:
            raise RuntimeError(f"Cannot append to invalid chain: {info}")
        self.prev_hash = info["last_event_hash"]
        self.count = info["event_count"]

    def append(self, event_core: Dict[str, Any]) -> Dict[str, Any]:
        event = dict(event_core)
        event["prev_event_hash"] = self.prev_hash
        event_hash = sha256_bytes(canonical_json(event))
        event["event_hash"] = event_hash
        if self.hmac_key is not None:
            event["event_hmac_sha256"] = hmac.new(
                self.hmac_key,
                bytes.fromhex(event_hash),
                hashlib.sha256,
            ).hexdigest()

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self.prev_hash = event_hash
        self.count += 1
        return event

    def write_head(self, out: Path):
        obj = {
            "schema": SCHEMA,
            "timestamp_utc": utc_now(),
            "event_count": self.count,
            "last_event_hash": self.prev_hash,
            "log_sha256": sha256_file(self.path),
            "hmac_enabled": self.hmac_key is not None,
        }
        if self.hmac_key is not None:
            obj["head_hmac_sha256"] = hmac.new(
                self.hmac_key,
                canonical_json({
                    "event_count": self.count,
                    "last_event_hash": self.prev_hash,
                    "log_sha256": obj["log_sha256"],
                }),
                hashlib.sha256,
            ).hexdigest()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
        return obj


def verify_log(path: Path, hmac_key: Optional[bytes],
               require_hmac: bool = False):
    prev = "0" * 64
    count = 0
    try:
        with path.open(encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                got_hash = event.pop("event_hash")
                got_hmac = event.pop("event_hmac_sha256", None)

                if event.get("prev_event_hash") != prev:
                    return False, {
                        "error": "prev_hash_mismatch",
                        "line": line_no,
                        "expected": prev,
                        "actual": event.get("prev_event_hash"),
                    }

                expected_hash = sha256_bytes(canonical_json(event))
                if not hmac.compare_digest(got_hash, expected_hash):
                    return False, {
                        "error": "event_hash_mismatch",
                        "line": line_no,
                    }

                if require_hmac and got_hmac is None:
                    return False, {"error": "missing_hmac", "line": line_no}

                if got_hmac is not None:
                    if hmac_key is None:
                        if require_hmac:
                            return False, {
                                "error": "hmac_key_required",
                                "line": line_no,
                            }
                    else:
                        expected_hmac = hmac.new(
                            hmac_key,
                            bytes.fromhex(got_hash),
                            hashlib.sha256,
                        ).hexdigest()
                        if not hmac.compare_digest(got_hmac, expected_hmac):
                            return False, {
                                "error": "event_hmac_mismatch",
                                "line": line_no,
                            }

                prev = got_hash
                count += 1

        return True, {
            "event_count": count,
            "last_event_hash": prev,
            "log_sha256": sha256_file(path),
        }
    except Exception as e:
        return False, {"error": repr(e)}


def extract_hidden(output):
    if torch.is_tensor(output):
        return output
    if isinstance(output, (tuple, list)) and output:
        if torch.is_tensor(output[0]):
            return output[0]
    for attr in ("last_hidden_state", "hidden_states"):
        v = getattr(output, attr, None)
        if torch.is_tensor(v):
            return v
    return None


def find_layer_stack(model, expected_layers: int):
    candidates = []
    for name, module in model.named_modules():
        if isinstance(module, torch.nn.ModuleList) and len(module) == expected_layers:
            score = 0
            lname = name.lower()
            if "layers" in lname:
                score += 4
            if "model" in lname:
                score += 1
            candidates.append((score, name, module))
    if not candidates:
        raise RuntimeError(
            f"Could not find a ModuleList with {expected_layers} transformer layers"
        )
    candidates.sort(key=lambda x: (x[0], len(x[1])), reverse=True)
    best = candidates[0]
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        print(
            "[warning] multiple layer-stack candidates found; using "
            f"{best[1]!r}. Candidates: {[x[1] for x in candidates[:5]]}",
            file=sys.stderr,
        )
    return best[1], best[2]


@dataclass
class RequestState:
    request_id: str
    prompt_id: str
    prompt_sha256: str
    started_utc: str
    started_monotonic_ns: int
    thinking: str
    settings_sha256: str
    captures: Dict[int, Dict[str, float]]


_ACTIVE: contextvars.ContextVar[Optional[RequestState]] = contextvars.ContextVar(
    "qwen_attestation_active", default=None
)


class PassiveActivationAttestor:
    def __init__(
        self,
        model,
        fingerprint_dir: Path,
        logger: ChainLogger,
        selected_depths: List[int],
        approved_activations_dir: Optional[Path] = None,
        model_ref: Optional[str] = None,
        model_revision: Optional[str] = None,
        model_manifest_path: Optional[Path] = None,
    ):
        self.model = model
        self.fingerprint_dir = fingerprint_dir
        self.logger = logger
        self.model_ref = model_ref
        self.model_revision = model_revision
        self.model_manifest_path = model_manifest_path
        self.handles = []

        fp_path = fingerprint_dir / "fingerprint.safetensors"
        fp_meta_path = fingerprint_dir / "fingerprint.json"
        fp = load_file(str(fp_path), device="cpu")
        self.directions = fp["directions"].float()
        self.safety_centroid = fp["approved_safety_centroid"].float()
        self.benign_centroid = fp["approved_benign_centroid"].float()
        self.fp_meta = json.loads(fp_meta_path.read_text(encoding="utf-8"))

        expected_layers = self.directions.shape[0] - 1
        self.architecture_adapter = choose_adapter(model_ref)
        self.layer_stack_name, self.layers = self.architecture_adapter.find_layers(
            model, expected_layers
        )
        self.depth_block_labels = {
            d: self.architecture_adapter.block_label(d - 1, self.layers[d - 1])
            for d in range(1, expected_layers + 1)
        }

        for d in selected_depths:
            if d < 1 or d > expected_layers:
                raise ValueError(
                    f"Selected depth {d} outside valid hooked depths 1..{expected_layers}"
                )
        self.selected_depths = sorted(set(selected_depths))

        self.reference_exact: Dict[str, torch.Tensor] = {}
        self.reference_records: Dict[str, Dict[str, Any]] = {}
        self.approved_activations_sha256 = None
        if approved_activations_dir is not None:
            meta_path = approved_activations_dir / "metadata.json"
            act_path = approved_activations_dir / "activations.safetensors"
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            acts = load_file(str(act_path), device="cpu")["activations"].float()
            if acts.shape[1:] != self.directions.shape:
                raise ValueError("Approved activation bundle shape does not match fingerprint")
            for i, rec in enumerate(meta["records"]):
                self.reference_exact[rec["id"]] = acts[i]
                self.reference_records[rec["id"]] = rec
            self.approved_activations_sha256 = sha256_file(act_path)

        self.fingerprint_sha256 = sha256_file(fp_path)
        self.fingerprint_meta_sha256 = sha256_file(fp_meta_path)
        self.model_manifest_sha256 = (
            sha256_file(model_manifest_path) if model_manifest_path else None
        )

    def attach(self):
        if self.handles:
            return
        for depth in self.selected_depths:
            module = self.layers[depth - 1]
            handle = module.register_forward_hook(
                self._make_hook(depth),
                prepend=False,
                with_kwargs=False,
                always_call=False,
            )
            self.handles.append(handle)

        self.logger.append({
            "schema": SCHEMA,
            "event_type": "attestor_start",
            "timestamp_utc": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "boot_id": read_boot_id(),
            "platform": platform.platform(),
            "python": sys.version,
            "packages": package_versions(),
            "process_cmdline_sha256": process_cmdline_sha256(),
            "model_ref": self.model_ref,
            "model_revision": self.model_revision,
            "model_manifest_sha256": self.model_manifest_sha256,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_meta_sha256": self.fingerprint_meta_sha256,
            "approved_activations_sha256": self.approved_activations_sha256,
            "layer_stack_name": self.layer_stack_name,
            "architecture_adapter": self.architecture_adapter.name,
            "selected_depths": self.selected_depths,
            "selected_depth_block_labels": {
                str(d): self.depth_block_labels.get(d) for d in self.selected_depths
            },
            "hook_semantics": "observation_only_return_none",
        })

    def detach(self):
        for h in self.handles:
            h.remove()
        self.handles.clear()
        self.logger.append({
            "schema": SCHEMA,
            "event_type": "attestor_stop",
            "timestamp_utc": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "pid": os.getpid(),
        })

    def _make_hook(self, depth: int):
        def hook(module, args, output):
            state = _ACTIVE.get()
            if state is None:
                return None
            if depth in state.captures:
                return None

            hidden = extract_hidden(output)
            if hidden is None or hidden.ndim < 2:
                return None
            if hidden.ndim == 2:
                vec = hidden[-1, :]
            else:
                if hidden.shape[0] != 1:
                    # v0.3 intentionally supports single-probe attestation only.
                    return None
                vec = hidden[0, -1, :]
            vec = vec.float()

            d = self.directions[depth].to(vec.device)
            sc = self.safety_centroid[depth].to(vec.device)
            bc = self.benign_centroid[depth].to(vec.device)

            measurements = {
                "projection_on_approved_direction": float(torch.dot(vec, d).item()),
                "activation_l2_norm": float(vec.norm().item()),
                "cosine_to_approved_safety_centroid": float(
                    F.cosine_similarity(vec[None, :], sc[None, :]).item()
                ),
                "cosine_to_approved_benign_centroid": float(
                    F.cosine_similarity(vec[None, :], bc[None, :]).item()
                ),
            }

            exact = self.reference_exact.get(state.prompt_id)
            if exact is not None:
                rv = exact[depth].to(vec.device)
                measurements.update({
                    "cosine_to_exact_approved_activation": float(
                        F.cosine_similarity(vec[None, :], rv[None, :]).item()
                    ),
                    "relative_l2_to_exact_approved_activation": float(
                        ((vec - rv).norm() / (rv.norm() + 1e-12)).item()
                    ),
                    "projection_delta_from_exact_approved": float(
                        (torch.dot(vec, d) - torch.dot(rv, d)).item()
                    ),
                })

            state.captures[depth] = measurements
            return None  # critical: passive observation only
        return hook

    def begin_request(
        self,
        prompt_id: str,
        prompt_text: str,
        thinking: str,
        generation_settings: Dict[str, Any],
    ):
        if _ACTIVE.get() is not None:
            raise RuntimeError("Nested attestation request is not supported")
        state = RequestState(
            request_id=str(uuid.uuid4()),
            prompt_id=prompt_id,
            prompt_sha256=sha256_bytes(prompt_text.encode("utf-8")),
            started_utc=utc_now(),
            started_monotonic_ns=time.monotonic_ns(),
            thinking=thinking,
            settings_sha256=sha256_bytes(canonical_json(generation_settings)),
            captures={},
        )
        token = _ACTIVE.set(state)
        return token, state

    def end_request(self, token, state: RequestState, status="ok",
                    generated_token_id: Optional[int] = None,
                    error: Optional[str] = None):
        _ACTIVE.reset(token)
        duration_ns = time.monotonic_ns() - state.started_monotonic_ns
        event = {
            "schema": SCHEMA,
            "event_type": "activation_attestation",
            "timestamp_utc": utc_now(),
            "request_id": state.request_id,
            "prompt_id": state.prompt_id,
            "prompt_sha256": state.prompt_sha256,
            "thinking": state.thinking,
            "generation_settings_sha256": state.settings_sha256,
            "status": status,
            "error": error,
            "duration_ns": duration_ns,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "boot_id": read_boot_id(),
            "model_ref": self.model_ref,
            "model_revision": self.model_revision,
            "model_manifest_sha256": self.model_manifest_sha256,
            "fingerprint_sha256": self.fingerprint_sha256,
            "approved_activations_sha256": self.approved_activations_sha256,
            "selected_depths": self.selected_depths,
            "captured_depths": sorted(state.captures),
            "captured_depth_block_labels": {
                str(d): self.depth_block_labels.get(d) for d in sorted(state.captures)
            },
            "measurements": {
                str(k): v for k, v in sorted(state.captures.items())
            },
        }
        if generated_token_id is not None:
            # Token ID is optional forensic metadata; generated text is never stored here.
            event["generated_token_id"] = int(generated_token_id)
        return self.logger.append(event)


def read_prompts(path: Path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                obj = json.loads(line)
                rows.append(obj)
    return rows


def get_model_input_device(model):
    try:
        emb = model.get_input_embeddings()
        if emb is not None and str(emb.weight.device) != "meta":
            return emb.weight.device
    except Exception:
        pass
    for p in model.parameters():
        if str(p.device) != "meta":
            return p.device
    raise RuntimeError("Unable to determine model input device")


def apply_chat(processor, prompt_text: str, thinking: str):
    messages = [{
        "role": "user",
        "content": [{"type": "text", "text": prompt_text}],
    }]
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
    except TypeError:
        kwargs.pop("enable_thinking", None)
        return processor.apply_chat_template(messages, **kwargs)


def load_qwen(model_ref: str, revision: Optional[str], dtype_name: str,
              device_map: str, local_files_only: bool):
    from transformers import AutoProcessor, AutoModelForMultimodalLM

    common = {
        "trust_remote_code": False,
        "local_files_only": local_files_only,
    }
    if revision:
        common["revision"] = revision

    processor = AutoProcessor.from_pretrained(model_ref, **common)
    kwargs = dict(common)
    kwargs.update({"device_map": device_map, "low_cpu_mem_usage": True})
    if dtype_name != "auto":
        kwargs["torch_dtype"] = {
            "bf16": torch.bfloat16,
            "fp16": torch.float16,
            "fp32": torch.float32,
        }[dtype_name]
    model = AutoModelForMultimodalLM.from_pretrained(model_ref, **kwargs)
    model.eval()
    return processor, model


def run_probe_set(args):
    hmac_key = load_hmac_key_from_env()
    logger = ChainLogger(Path(args.log), hmac_key=hmac_key)

    processor, model = load_qwen(
        args.model, args.revision, args.dtype, args.device_map,
        args.local_files_only,
    )
    depths = [int(x) for x in args.depths.split(",") if x.strip()]

    attestor = PassiveActivationAttestor(
        model=model,
        fingerprint_dir=Path(args.fingerprint),
        logger=logger,
        selected_depths=depths,
        approved_activations_dir=(
            Path(args.approved_activations) if args.approved_activations else None
        ),
        model_ref=args.model,
        model_revision=args.revision,
        model_manifest_path=(
            Path(args.model_manifest) if args.model_manifest else None
        ),
    )
    attestor.attach()
    device = get_model_input_device(model)

    prompts = read_prompts(Path(args.prompts))
    try:
        for i, item in enumerate(prompts, 1):
            prompt_text = item["prompt"]
            prompt_id = item["id"]
            inputs = apply_chat(processor, prompt_text, args.thinking)
            if hasattr(inputs, "to"):
                inputs = inputs.to(device)
            else:
                inputs = {
                    k: (v.to(device) if torch.is_tensor(v) else v)
                    for k, v in inputs.items()
                }

            settings = {
                "mode": args.mode,
                "max_new_tokens": 1 if args.mode == "generate" else 0,
                "do_sample": False,
                "thinking": args.thinking,
            }
            token, state = attestor.begin_request(
                prompt_id, prompt_text, args.thinking, settings
            )
            generated_token_id = None
            try:
                with torch.inference_mode():
                    if args.mode == "generate":
                        out = model.generate(
                            **inputs,
                            max_new_tokens=1,
                            do_sample=False,
                        )
                        # Store only the one generated token ID, never decoded text.
                        in_len = int(inputs["input_ids"].shape[-1])
                        if out.ndim == 2 and out.shape[-1] > in_len:
                            generated_token_id = int(out[0, in_len].item())
                    else:
                        model(
                            **inputs,
                            use_cache=False,
                            return_dict=True,
                            logits_to_keep=1,
                        )
                event = attestor.end_request(
                    token, state, status="ok",
                    generated_token_id=generated_token_id,
                )
                print(
                    f"[attest] {i}/{len(prompts)} {prompt_id} "
                    f"captured={event['captured_depths']}",
                    flush=True,
                )
            except Exception as e:
                attestor.end_request(
                    token, state, status="error", error=repr(e)
                )
                raise
    finally:
        attestor.detach()
        head = logger.write_head(Path(args.head))
        print(json.dumps(head, indent=2, sort_keys=True))


def verify_cmd(args):
    key = load_hmac_key_from_env()
    ok, info = verify_log(
        Path(args.log), key, require_hmac=args.require_hmac
    )
    print(json.dumps({"valid": ok, **info}, indent=2, sort_keys=True))
    if not ok:
        raise SystemExit(1)


# ---------------- synthetic self-test ----------------

class ToyBlock(torch.nn.Module):
    def __init__(self, hidden, offset=0.0):
        super().__init__()
        self.linear = torch.nn.Linear(hidden, hidden, bias=False)
        torch.nn.init.eye_(self.linear.weight)
        self.offset = offset

    def forward(self, x):
        return self.linear(x) + self.offset


class ToyModel(torch.nn.Module):
    def __init__(self, layers=4, hidden=8, tamper_depth=None):
        super().__init__()
        self.layers = torch.nn.ModuleList()
        for i in range(layers):
            self.layers.append(
                ToyBlock(hidden, offset=(0.5 if tamper_depth == i + 1 else 0.0))
            )

    def forward(self, x):
        for layer in self.layers:
            x = layer(x)
        return x


def selftest(out_dir: Path):
    from safetensors.torch import save_file

    out_dir.mkdir(parents=True, exist_ok=True)
    fp_dir = out_dir / "fingerprint"
    ref_dir = out_dir / "approved_activations"
    fp_dir.mkdir(exist_ok=True)
    ref_dir.mkdir(exist_ok=True)

    torch.manual_seed(7)
    layers, hidden = 4, 8
    directions = torch.randn(layers + 1, hidden)
    directions = directions / directions.norm(dim=-1, keepdim=True)
    safety = torch.randn(layers + 1, hidden)
    benign = torch.randn(layers + 1, hidden)

    save_file({
        "directions": directions,
        "approved_safety_centroid": safety,
        "approved_benign_centroid": benign,
    }, str(fp_dir / "fingerprint.safetensors"))
    (fp_dir / "fingerprint.json").write_text(json.dumps({
        "approved_model_ref": "toy-approved",
        "approved_revision": "toy",
    }), encoding="utf-8")

    # Reference exact activation for one toy probe.
    x = torch.randn(1, 3, hidden)
    approved = ToyModel(layers=layers, hidden=hidden)
    per_depth = [x[0, -1, :].detach().clone()]
    cur = x
    for block in approved.layers:
        cur = block(cur)
        per_depth.append(cur[0, -1, :].detach().clone())
    acts = torch.stack(per_depth)[None, :, :]
    save_file({"activations": acts}, str(ref_dir / "activations.safetensors"))
    (ref_dir / "metadata.json").write_text(json.dumps({
        "records": [{
            "id": "toy_probe",
            "expected_refusal": True,
            "prompt_sha256": sha256_bytes(b"toy"),
        }]
    }), encoding="utf-8")

    log = out_dir / "attestation.jsonl"
    logger = ChainLogger(log, hmac_key=b"A" * 32)
    suspect = ToyModel(layers=layers, hidden=hidden, tamper_depth=3)
    att = PassiveActivationAttestor(
        suspect, fp_dir, logger, [1, 2, 3, 4],
        approved_activations_dir=ref_dir,
        model_ref="toy-suspect",
        model_revision="toy",
    )
    att.attach()
    token, state = att.begin_request(
        "toy_probe", "toy", "off", {"mode": "forward"}
    )
    suspect(x)
    event = att.end_request(token, state)
    att.detach()
    logger.write_head(out_dir / "chain_head.json")

    if event["captured_depths"] != [1, 2, 3, 4]:
        raise RuntimeError("selftest failed to capture all depths")
    # Tamper at depth 3 should produce non-zero exact-reference delta there.
    d3 = event["measurements"]["3"]["relative_l2_to_exact_approved_activation"]
    if d3 <= 0.01:
        raise RuntimeError("selftest failed to detect synthetic runtime divergence")

    ok, info = verify_log(log, b"A" * 32, require_hmac=True)
    if not ok:
        raise RuntimeError(f"selftest chain verification failed: {info}")

    # Verify modification detection by corrupting a copy.
    corrupt = out_dir / "attestation_corrupt.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["status"] = "corrupted"
    lines[1] = json.dumps(obj, sort_keys=True)
    corrupt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, _ = verify_log(corrupt, b"A" * 32, require_hmac=True)
    if ok2:
        raise RuntimeError("selftest failed: corrupt chain was accepted")

    result = {
        "status": "PASS",
        "captured_depths": event["captured_depths"],
        "synthetic_depth3_relative_l2": d3,
        "valid_chain_accepted": ok,
        "corrupt_chain_rejected": not ok2,
        "event_count": info["event_count"],
    }
    (out_dir / "SELFTEST.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def build_parser():
    ap = argparse.ArgumentParser(
        description="Passive live activation attestation for Qwen3.8"
    )
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser(
        "probe",
        help="Run a one-token/forward probe set through a live-loaded model and attest selected depths",
    )
    p.add_argument("--model", required=True)
    p.add_argument("--revision", default=None)
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--approved-activations", default=None)
    p.add_argument("--model-manifest", default=None)
    p.add_argument("--prompts", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--depths", default="16,24,32,36,40,44,48,56,64")
    p.add_argument("--thinking", choices=["off", "on", "default"], default="off")
    p.add_argument("--mode", choices=["generate", "forward"], default="generate")
    p.add_argument("--dtype", choices=["auto", "bf16", "fp16", "fp32"], default="bf16")
    p.add_argument("--device-map", default="auto")
    p.add_argument("--local-files-only", action="store_true")

    p = sp.add_parser("verify", help="Verify the JSONL hash/HMAC chain")
    p.add_argument("--log", required=True)
    p.add_argument("--require-hmac", action="store_true")

    p = sp.add_parser("selftest", help="Run passive hook + chain-integrity synthetic test")
    p.add_argument("--out", required=True)

    return ap


def main():
    args = build_parser().parse_args()
    if args.cmd == "probe":
        run_probe_set(args)
    elif args.cmd == "verify":
        verify_cmd(args)
    elif args.cmd == "selftest":
        selftest(Path(args.out))


if __name__ == "__main__":
    main()
