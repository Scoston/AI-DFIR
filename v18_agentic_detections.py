"""Evidence-gated agentic detections for AI-DFIR v1.8.

Rules only emit when an explicit observed boolean signal is present in retained
node attributes. Absence of a signal is not treated as proof of absence.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from v18_agent_execution_record import canonical_bytes, sha256_bytes, validate_record

SCHEMA = "ai-dfir/agentic-detection-report/v1.8"
OWASP_VERSION = "Top 10 for Agentic Applications 2026"
ATLAS_PROFILE = "MITRE ATLAS Agentic AI"

RULES = {
    "ASI01": {"name": "Agent Goal Hijack", "signals": ["goal_changed_without_approval", "untrusted_instruction_influenced_goal"],
              "atlas": ["LLM Prompt Injection", "AI Agent Context Poisoning"]},
    "ASI02": {"name": "Tool Misuse & Exploitation", "signals": ["tool_policy_violation", "unsafe_tool_invocation"],
              "atlas": ["AI Agent Tool Invocation", "AI Agent Tool Poisoning"]},
    "ASI03": {"name": "Identity & Privilege Abuse", "signals": ["authority_exceeded", "delegated_identity_misused"],
              "atlas": ["Valid Accounts", "AI Agent Tool Invocation"]},
    "ASI04": {"name": "Agentic Supply Chain Vulnerabilities", "signals": ["component_integrity_failed", "tool_schema_untrusted"],
              "atlas": ["AI Agent Tool Poisoning", "Modify AI Agent Configuration"]},
    "ASI05": {"name": "Unexpected Code Execution (RCE)", "signals": ["unexpected_code_execution", "sandbox_escape_observed"],
              "atlas": ["Command and Scripting Interpreter", "Escape to Host"]},
    "ASI06": {"name": "Memory & Context Poisoning", "signals": ["memory_integrity_failed", "untrusted_context_persisted"],
              "atlas": ["AI Agent Context Poisoning", "RAG Poisoning"]},
    "ASI07": {"name": "Insecure Inter-Agent Communication", "signals": ["inter_agent_authentication_failed", "spoofed_agent_message"],
              "atlas": ["AI Agent Context Poisoning", "AI Agent Tool Invocation"]},
    "ASI08": {"name": "Cascading Failures", "signals": ["cascading_failure", "downstream_automation_amplified_error"],
              "atlas": ["Deploy AI Agent", "AI Agent Tool Invocation"]},
    "ASI09": {"name": "Human-Agent Trust Exploitation", "signals": ["human_approval_induced_by_untrusted_content", "misleading_agent_explanation_observed"],
              "atlas": ["AI Agent Clickbait", "LLM Prompt Injection"]},
    "ASI10": {"name": "Rogue Agents", "signals": ["agent_policy_evasion", "self_directed_action_outside_goal"],
              "atlas": ["Modify AI Agent Configuration", "Deploy AI Agent"]},
}


def evaluate(record: dict[str, Any]) -> dict[str, Any]:
    validate_record(record)
    findings: list[dict[str, Any]] = []
    for node in record["nodes"]:
        attrs = node["attributes"]
        for risk_id, rule in RULES.items():
            matched = [name for name in rule["signals"] if attrs.get(name) is True]
            if not matched:
                continue
            refs = deepcopy(node.get("evidence_refs", []))
            findings.append({
                "risk_id": risk_id,
                "risk_name": rule["name"],
                "node_id": node["node_id"],
                "matched_observed_signals": matched,
                "atlas_technique_names": list(rule["atlas"]),
                "evidence_refs": refs,
                "confidence": "observed-signal" if refs else "signal-without-bound-evidence",
                "conclusion": "review-required",
            })
    report = {
        "schema": SCHEMA,
        "source_record_id": record["record_id"],
        "source_record_sha256": record["record_sha256"],
        "framework_versions": {"owasp_agentic": OWASP_VERSION, "mitre_atlas": ATLAS_PROFILE},
        "findings": findings,
        "claims": {"attack_proven": False, "framework_mapping_is_detection": False,
                   "absence_of_findings_proves_safety": False},
    }
    report["report_sha256"] = sha256_bytes(canonical_bytes(report))
    return report
