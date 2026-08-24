# v0.3 Live Execution Attestation Runbook

## Goal

Detect a runtime-only model-integrity intervention even when the on-disk Qwen3.8 checkpoint is pristine.

Examples include:
- a forward hook that alters hidden states,
- a loaded control vector,
- an adapter applied only in memory,
- a serving wrapper that modifies intermediate representations.

v0.3 uses **observation-only** hooks. It does not modify model outputs.

## Threat model

A local SHA-256 manifest proves which files were acquired. It cannot prove that the running process used those artifacts without intervention.

v0.3 binds:

```text
process identity
model-manifest hash
approved-fingerprint hash
approved-activation hash
prompt hash
generation-settings hash
selected residual-depth measurements
timestamp / boot ID / PID
previous attestation event hash
```

into each attestation event.

## 1. Test the attestor

```bash
python live_attestation.py selftest \
  --out /tmp/qwen_live_attestation_selftest
```

Expected:

```text
"status": "PASS"
"valid_chain_accepted": true
"corrupt_chain_rejected": true
```

## 2. Create an HMAC key

Do this in a secrets-management system if possible.

For a lab:

```bash
python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
```

Set it only for the attestation process:

```bash
export QWEN_ATTESTATION_HMAC_KEY_HEX='<64 hex characters>'
```

**Production:** do not persist this key in shell history, image layers, source, or ordinary model-server environment dumps. Prefer short-lived injection from a secret manager or a remote signer.

## 3. Use the approved v0.2 fingerprint

You need:

```text
/evidence/case001/fingerprint/
/evidence/case001/approved_activations/
```

These must have been derived from the approved checkpoint under the same:
- chat template
- tokenizer
- thinking mode
- dtype/quantization baseline
- Transformers version
- probe set

## 4. Generate a current deployed-model manifest

```bash
python qwen_forensic_detector.py manifest \
  /srv/models/qwen38-deployed \
  --out /evidence/case001/deployed_manifest.json
```

## 5. Run a live one-token attestation probe

The default `generate` mode traverses the generation path but generates **only one token**, which is discarded and never decoded to text by the attestor.

```bash
python live_attestation.py probe \
  --model /srv/models/qwen38-deployed \
  --local-files-only \
  --fingerprint /evidence/case001/fingerprint \
  --approved-activations /evidence/case001/approved_activations \
  --model-manifest /evidence/case001/deployed_manifest.json \
  --prompts prompts/activation_probe.jsonl \
  --thinking off \
  --dtype bf16 \
  --depths 16,24,32,36,40,44,48,56,64 \
  --log /evidence/case001/live/events.jsonl \
  --head /evidence/case001/live/chain_head.json
```

The log records prompt hashes and measurements. It does **not** store prompt text or decoded model response text.

## 6. Verify the chain

```bash
python live_attestation.py verify \
  --log /evidence/case001/live/events.jsonl \
  --require-hmac
```

or:

```bash
python verify_attestation_log.py \
  --log /evidence/case001/live/events.jsonl \
  --require-hmac
```

## 7. What to review

For each selected residual depth:

- `projection_on_approved_direction`
- `cosine_to_approved_safety_centroid`
- `cosine_to_approved_benign_centroid`
- `cosine_to_exact_approved_activation`
- `relative_l2_to_exact_approved_activation`
- `projection_delta_from_exact_approved`

The exact-activation metrics require the same probe ID to exist in the approved activation bundle.

## 8. Interpretation

A runtime-only refusal-vector intervention may produce a pattern such as:

```text
depth 24  exact cosine 0.999
depth 32  exact cosine 0.998
depth 36  exact cosine 0.91
depth 40  exact cosine 0.73
depth 48  exact cosine 0.68
```

while the deployed model files still hash identically to the approved checkpoint.

Do not use those example numbers as thresholds.

Build local baselines from:
1. repeated approved deployments,
2. each approved precision/quantization,
3. each serving framework/version,
4. thinking-on and thinking-off configurations.

## 9. Evidence hardening

A hash chain stored on the same compromised host is not enough against root compromise.

Preferred design:

```text
Inference host
   |
   +-- event hash/HMAC
   |
   v
remote collector / SIEM / WORM
   |
   +-- timestamp
   +-- host identity
   +-- event hash
   +-- chain head
```

Export either every event or, at minimum, frequent chain heads to a separate trust domain.

## 10. Production integration

See:

```text
production_integration_example.py
```

The `PassiveActivationAttestor` attaches normal PyTorch `register_forward_hook` observers and returns `None` from every hook. PyTorch forward hooks execute after a module's `forward()` has produced its output; a hook can alter that output, which is exactly why the v0.3 observer is explicitly written never to return a replacement value.

## Current limitation

The standalone `probe` command loads the model itself. That detects checkpoint-contained changes and any hooks/adapters present in that analysis process.

For a **true runtime-only** production intervention, integrate `PassiveActivationAttestor` into the already-running production inference process or equivalent serving worker. Otherwise, reconstructing the checkpoint in a clean lab removes the runtime-only intervention you are trying to observe.


## 11. Summarize the live evidence

```bash
python summarize_live_attestation.py \
  --log /evidence/case001/live/events.jsonl \
  --out /evidence/case001/live/summary
```

Outputs:

```text
summary/
  depth_summary.csv
  live_attestation_summary.md
```

The report ranks depths using observed exact-reference cosine, relative L2
divergence, and approved-direction projection delta. It deliberately does not
apply a universal tampering threshold.
