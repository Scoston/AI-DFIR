#!/usr/bin/env python3
"""Fleet policy evaluation and drift-state machine."""
from __future__ import annotations
import math
from typing import Dict, Any, List


SEVERITY = {"info": 10, "low": 20, "medium": 30, "high": 40, "critical": 50}


def finding(code, severity, message, **evidence):
    return {
        "code": code,
        "severity": severity,
        "severity_score": SEVERITY[severity],
        "message": message,
        "evidence": evidence,
    }


def evaluate(payload: Dict[str, Any], node_policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    f = []

    approved = node_policy.get("approved", {})
    observed = payload.get("observed", {})

    exact_checks = [
        ("model_manifest_sha256", "MODEL_MANIFEST_DRIFT", "critical"),
        ("model_tree_content_sha256", "MODEL_CONTENT_TREE_DRIFT", "critical"),
        ("fingerprint_sha256", "FINGERPRINT_DRIFT", "critical"),
        ("approved_activations_sha256", "ACTIVATION_REFERENCE_DRIFT", "high"),
        ("runtime_inventory_sha256", "RUNTIME_INVENTORY_DRIFT", "high"),
        ("container_image_digest", "CONTAINER_IMAGE_DRIFT", "high"),
        ("chat_template_sha256", "CHAT_TEMPLATE_DRIFT", "high"),
        ("tokenizer_sha256", "TOKENIZER_DRIFT", "high"),
        ("authority_policy_sha256", "DELEGATED_AUTHORITY_DRIFT", "critical"),
        ("tool_schema_sha256", "TOOL_SCHEMA_DRIFT", "high"),
        ("retrieval_config_sha256", "RETRIEVAL_CONFIG_DRIFT", "high"),
    ]
    for field, code, sev in exact_checks:
        want = approved.get(field)
        got = observed.get(field)
        if want is not None and got != want:
            f.append(finding(code, sev, f"{field} differs from approved state", approved=want, observed=got))

    allowed_raw=node_policy.get("allowed_adapters", [])
    observed_raw=observed.get("active_adapters") or []
    if isinstance(allowed_raw,str): allowed_raw=[allowed_raw]
    if isinstance(observed_raw,str): observed_raw=[observed_raw]
    allowed_adapters = set(allowed_raw)
    adapters = set(observed_raw)
    unexpected_adapters = sorted(adapters - allowed_adapters)
    if unexpected_adapters:
        f.append(finding(
            "UNEXPECTED_ADAPTER", "critical",
            "Runtime has unapproved active adapter(s)",
            unexpected=unexpected_adapters,
            allowed=sorted(allowed_adapters),
        ))

    approved_hooks = set(node_policy.get("approved_hook_fingerprints", []))
    hook_fps = set(observed.get("hook_fingerprints") or [])
    unexpected_hooks = sorted(hook_fps - approved_hooks)
    if unexpected_hooks:
        f.append(finding(
            "UNEXPECTED_RUNTIME_HOOK", "critical",
            "Runtime has unapproved Python hook fingerprint(s)",
            unexpected=unexpected_hooks,
        ))

    div = payload.get("divergence", {})
    z = div.get("highest_abs_robust_z")
    crit_z = float(node_policy.get("critical_robust_z", 10.0))
    high_z = float(node_policy.get("high_robust_z", 5.0))
    if isinstance(z, (int, float)) and math.isfinite(float(z)):
        if z >= crit_z:
            f.append(finding("ACTIVATION_DRIFT_CRITICAL", "critical",
                             "Activation divergence exceeds critical approved-baseline threshold",
                             highest_abs_robust_z=z,
                             first_divergence_depth=div.get("first_material_divergence_depth")))
        elif z >= high_z:
            f.append(finding("ACTIVATION_DRIFT_HIGH", "high",
                             "Activation divergence exceeds approved-baseline threshold",
                             highest_abs_robust_z=z,
                             first_divergence_depth=div.get("first_material_divergence_depth")))

    chain = payload.get("attestation_chain", {})
    if chain.get("valid") is False:
        f.append(finding("ATTESTATION_CHAIN_INVALID", "critical",
                         "Local live-attestation chain failed verification"))

    hardware = payload.get("hardware_attestation", {})
    if node_policy.get("require_hardware_attestation"):
        if hardware.get("verification_status") != "verified":
            f.append(finding("HARDWARE_ATTESTATION_NOT_VERIFIED", "high",
                             "Required hardware attestation is not verified",
                             status=hardware.get("verification_status")))
        elif hardware.get("overall_result") is not True:
            f.append(finding("HARDWARE_ATTESTATION_FAILED", "critical",
                             "Verified hardware attestation reports failure"))

    if payload.get("quick_integrity", {}).get("metadata_tree_changed") is True:
        f.append(finding("MODEL_TREE_METADATA_CHANGED", "medium",
                         "Model directory metadata tree changed; schedule full cryptographic re-hash"))

    return sorted(f, key=lambda x: x["severity_score"], reverse=True)


def aggregate_state(findings, previous_state="NORMAL", recovery_streak=0, recovery_required=3):
    max_score = max([x["severity_score"] for x in findings], default=0)
    if max_score >= SEVERITY["critical"]:
        return "CRITICAL", 0
    if max_score >= SEVERITY["high"]:
        return "ALERT", 0
    if max_score >= SEVERITY["medium"]:
        return "OBSERVE", 0

    if previous_state in ("CRITICAL", "ALERT", "OBSERVE"):
        recovery_streak += 1
        if recovery_streak >= recovery_required:
            return "RECOVERED", recovery_streak
        return previous_state, recovery_streak
    if previous_state == "RECOVERED":
        return "NORMAL", 0
    return "NORMAL", 0
