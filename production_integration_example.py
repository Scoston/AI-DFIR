"""
Minimal integration example for an existing Python/Transformers inference process.

IMPORTANT:
- This class is an observer. It must never return replacement activations.
- Install it after your model is loaded.
- For production, export `chain_head.json` or every event hash to a remote
  append-only SIEM/WORM target. A local-only chain cannot defeat a root-level
  attacker who can rewrite both logs and keys.
"""

from pathlib import Path
from live_attestation import (
    ChainLogger,
    PassiveActivationAttestor,
    load_hmac_key_from_env,
)

logger = ChainLogger(
    Path("/var/log/qwen-attestation/events.jsonl"),
    hmac_key=load_hmac_key_from_env(),
)

attestor = PassiveActivationAttestor(
    model=model,  # your already-loaded Qwen3.8 model
    fingerprint_dir=Path("/opt/qwen-attestation/fingerprint"),
    approved_activations_dir=Path("/opt/qwen-attestation/approved_activations"),
    logger=logger,
    selected_depths=[16, 24, 32, 36, 40, 44, 48, 56, 64],
    model_ref="Qwen/Qwen3.8-27B",
    model_revision="<approved-or-deployed-revision>",
    model_manifest_path=Path("/opt/qwen-attestation/deployed_manifest.json"),
)

attestor.attach()

# Around a controlled attestation/canary request:
settings = {
    "mode": "production_generation",
    "temperature": 0.0,
    "thinking": "off",
}

token, state = attestor.begin_request(
    prompt_id="canary_001",
    prompt_text=controlled_prompt_text,
    thinking="off",
    generation_settings=settings,
)

try:
    # Call the same inference path production uses.
    output = model.generate(**inputs, max_new_tokens=1, do_sample=False)
    attestor.end_request(token, state, status="ok")
except Exception as e:
    attestor.end_request(token, state, status="error", error=repr(e))
    raise

# At shutdown:
attestor.detach()
logger.write_head(Path("/var/log/qwen-attestation/chain_head.json"))
