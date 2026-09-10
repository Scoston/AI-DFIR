"""Evidence-bound differential execution comparison for AI-DFIR v1.8.

The comparator describes observable differences between two validated Agent
Execution Records (AERs). It does not infer compromise, regression, intent,
semantic equivalence, or causality from drift alone.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Iterable

import v18_agent_execution_record as aer

SCHEMA = "ai-dfir/differential-execution/v1.8"
MAX_MATCHES = 100_000
MAX_CHANGES = 250_000


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _diff(expected: Any, observed: Any, *, path: str = "") -> list[dict[str, Any]]:
    """Return deterministic JSON-pointer differences without guessing semantics."""
    if type(expected) is not type(observed):
        return [{"path": path or "/", "expected": deepcopy(expected), "observed": deepcopy(observed)}]
    if isinstance(expected, dict):
        changes: list[dict[str, Any]] = []
        keys = sorted(set(expected) | set(observed))
        for key in keys:
            child = f"{path}/{_pointer_token(str(key))}"
            if key not in expected:
                changes.append({"path": child, "expected": None, "observed": deepcopy(observed[key]), "presence": "added"})
            elif key not in observed:
                changes.append({"path": child, "expected": deepcopy(expected[key]), "observed": None, "presence": "removed"})
            else:
                changes.extend(_diff(expected[key], observed[key], path=child))
            if len(changes) > MAX_CHANGES:
                raise ValueError("comparison change count exceeds bound")
        return changes
    if isinstance(expected, list):
        if aer.canonical_bytes(expected) == aer.canonical_bytes(observed):
            return []
        return [{"path": path or "/", "expected": deepcopy(expected), "observed": deepcopy(observed)}]
    if expected != observed:
        return [{"path": path or "/", "expected": deepcopy(expected), "observed": deepcopy(observed)}]
    return []


def _validate_mapping(mapping: dict[str, str] | None, *, name: str,
                      expected_ids: set[str], observed_ids: set[str]) -> dict[str, str]:
    if mapping is None:
        return {}
    if not isinstance(mapping, dict) or len(mapping) > MAX_MATCHES:
        raise ValueError(f"{name} must be a bounded object")
    result: dict[str, str] = {}
    used: set[str] = set()
    for expected_id, observed_id in sorted(mapping.items()):
        _text(expected_id, f"{name} expected id")
        _text(observed_id, f"{name} observed id")
        if expected_id not in expected_ids:
            raise ValueError(f"{name} references missing expected id: {expected_id}")
        if observed_id not in observed_ids:
            raise ValueError(f"{name} references missing observed id: {observed_id}")
        if observed_id in used:
            raise ValueError(f"{name} must be one-to-one")
        result[expected_id] = observed_id
        used.add(observed_id)
    return result


def _complete_matches(expected_ids: set[str], observed_ids: set[str],
                      explicit: dict[str, str]) -> dict[str, str]:
    """Add exact-ID matches only when they do not conflict with explicit mappings."""
    matched = dict(explicit)
    used_observed = set(explicit.values())
    for value in sorted(expected_ids & observed_ids):
        if value in matched or value in used_observed:
            continue
        matched[value] = value
        used_observed.add(value)
    return matched


def _ref_identity(ref: dict[str, Any]) -> str:
    return aer.sha256_bytes(aer.canonical_bytes(ref))


def _reference_delta(expected: Iterable[dict[str, Any]], observed: Iterable[dict[str, Any]]) -> dict[str, Any]:
    exp = {_ref_identity(item): deepcopy(item) for item in expected}
    obs = {_ref_identity(item): deepcopy(item) for item in observed}
    return {
        "added": [obs[key] for key in sorted(set(obs) - set(exp))],
        "removed": [exp[key] for key in sorted(set(exp) - set(obs))],
    }


def _time_seconds(value: str) -> float | None:
    try:
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(candidate)
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _duration(record: dict[str, Any]) -> float | None:
    if record.get("ended_at") is None:
        return None
    start, end = _time_seconds(record["started_at"]), _time_seconds(record["ended_at"])
    return None if start is None or end is None else end - start


def _node_category(kind: str) -> str:
    return {
        "model": "model", "context": "prompt_context", "retrieval": "retrieval",
        "memory": "memory", "policy": "policy", "approval": "approval",
        "identity": "identity_authority", "human": "identity_authority", "agent": "agent",
        "tool": "tool", "protocol": "protocol", "side_effect": "side_effect",
        "action": "side_effect", "resource": "side_effect", "task": "agent",
        "message": "prompt_context", "artifact": "side_effect", "workflow": "workflow",
        "trigger": "workflow", "unknown": "unknown",
    }.get(kind, "unknown")


def _changed_categories(node_changes: list[dict[str, Any]], edge_changes: list[dict[str, Any]],
                        source_version_changes: dict[str, Any]) -> list[str]:
    categories: set[str] = set()
    for change in node_changes:
        categories.add(_node_category(change.get("expected_kind") or change.get("observed_kind") or "unknown"))
        paths = {item["path"] for item in change.get("attribute_changes", [])}
        text = " ".join(paths).lower()
        for token, category in (("model", "model"), ("prompt", "prompt_context"), ("instruction", "prompt_context"),
                                ("retriev", "retrieval"), ("chunk", "retrieval"), ("memory", "memory"),
                                ("policy", "policy"), ("approval", "approval"), ("credential", "identity_authority"),
                                ("identity", "identity_authority"), ("authority", "identity_authority"),
                                ("tool", "tool"), ("protocol", "protocol"), ("side", "side_effect")):
            if token in text:
                categories.add(category)
    for change in edge_changes:
        if change.get("authority_context_changes"):
            categories.add("identity_authority")
        if change.get("policy_context_changes"):
            categories.add("policy")
        if change.get("approval_context_changes"):
            categories.add("approval")
        if change.get("relationship_changed") or change.get("endpoint_changed"):
            categories.add("execution_graph")
    if source_version_changes:
        categories.add("source_version")
    return sorted(categories)


def compare_executions(expected: dict[str, Any], observed: dict[str, Any], *,
                       comparison_id: str,
                       node_matches: dict[str, str] | None = None,
                       edge_matches: dict[str, str] | None = None) -> dict[str, Any]:
    """Compare two AERs with exact IDs plus optional explicit one-to-one mappings."""
    aer.validate_record(expected)
    aer.validate_record(observed)
    _text(comparison_id, "comparison_id")

    exp_nodes = {item["node_id"]: item for item in expected["nodes"]}
    obs_nodes = {item["node_id"]: item for item in observed["nodes"]}
    explicit_nodes = _validate_mapping(node_matches, name="node_matches",
                                       expected_ids=set(exp_nodes), observed_ids=set(obs_nodes))
    matched_nodes = _complete_matches(set(exp_nodes), set(obs_nodes), explicit_nodes)

    node_changes: list[dict[str, Any]] = []
    node_timing: list[dict[str, Any]] = []
    for expected_id, observed_id in sorted(matched_nodes.items()):
        left, right = exp_nodes[expected_id], obs_nodes[observed_id]
        attribute_changes = _diff(left["attributes"], right["attributes"], path="/attributes")
        evidence_changes = _reference_delta(left["evidence_refs"], right["evidence_refs"])
        kind_changed = left["kind"] != right["kind"]
        if kind_changed or attribute_changes or evidence_changes["added"] or evidence_changes["removed"]:
            node_changes.append({
                "expected_node_id": expected_id, "observed_node_id": observed_id,
                "match_basis": "explicit" if expected_id in explicit_nodes else "exact-id",
                "expected_kind": left["kind"], "observed_kind": right["kind"],
                "kind_changed": kind_changed, "attribute_changes": attribute_changes,
                "evidence_reference_changes": evidence_changes,
            })
        if left["observed_at"] != right["observed_at"]:
            left_seconds, right_seconds = _time_seconds(left["observed_at"]), _time_seconds(right["observed_at"])
            node_timing.append({
                "expected_node_id": expected_id, "observed_node_id": observed_id,
                "expected_observed_at": left["observed_at"], "observed_observed_at": right["observed_at"],
                "delta_seconds": None if left_seconds is None or right_seconds is None else right_seconds - left_seconds,
            })

    expected_unmatched_nodes = sorted(set(exp_nodes) - set(matched_nodes))
    observed_unmatched_nodes = sorted(set(obs_nodes) - set(matched_nodes.values()))

    exp_edges = {item["edge_id"]: item for item in expected["edges"]}
    obs_edges = {item["edge_id"]: item for item in observed["edges"]}
    explicit_edges = _validate_mapping(edge_matches, name="edge_matches",
                                       expected_ids=set(exp_edges), observed_ids=set(obs_edges))
    matched_edges = _complete_matches(set(exp_edges), set(obs_edges), explicit_edges)
    edge_changes: list[dict[str, Any]] = []
    for expected_id, observed_id in sorted(matched_edges.items()):
        left, right = exp_edges[expected_id], obs_edges[observed_id]
        mapped_source = matched_nodes.get(left["source_node"])
        mapped_target = matched_nodes.get(left["target_node"])
        endpoint_changed = mapped_source != right["source_node"] or mapped_target != right["target_node"]
        relationship_changed = left["relationship"] != right["relationship"]
        authority_changes = _diff(left["authority_context"], right["authority_context"], path="/authority_context")
        policy_changes = _diff(left["policy_context"], right["policy_context"], path="/policy_context")
        approval_changes = _diff(left["approval_context"], right["approval_context"], path="/approval_context")
        evidence_changes = _reference_delta(left["evidence_refs"], right["evidence_refs"])
        confidence_changed = left["confidence"] != right["confidence"]
        unknown_changes = _diff(sorted(left["unknown_fields"]), sorted(right["unknown_fields"]), path="/unknown_fields")
        if (endpoint_changed or relationship_changed or authority_changes or policy_changes or approval_changes
                or evidence_changes["added"] or evidence_changes["removed"] or confidence_changed or unknown_changes):
            edge_changes.append({
                "expected_edge_id": expected_id, "observed_edge_id": observed_id,
                "match_basis": "explicit" if expected_id in explicit_edges else "exact-id",
                "expected_relationship": left["relationship"], "observed_relationship": right["relationship"],
                "relationship_changed": relationship_changed,
                "expected_source_node": left["source_node"], "observed_source_node": right["source_node"],
                "expected_target_node": left["target_node"], "observed_target_node": right["target_node"],
                "endpoint_changed": endpoint_changed,
                "authority_context_changes": authority_changes,
                "policy_context_changes": policy_changes,
                "approval_context_changes": approval_changes,
                "evidence_reference_changes": evidence_changes,
                "expected_confidence": left["confidence"], "observed_confidence": right["confidence"],
                "confidence_changed": confidence_changed,
                "unknown_field_changes": unknown_changes,
            })

    expected_unmatched_edges = sorted(set(exp_edges) - set(matched_edges))
    observed_unmatched_edges = sorted(set(obs_edges) - set(matched_edges.values()))
    version_keys = sorted(set(expected["source_versions"]) | set(observed["source_versions"]))
    source_version_changes = {
        key: {"expected": expected["source_versions"].get(key), "observed": observed["source_versions"].get(key)}
        for key in version_keys if expected["source_versions"].get(key) != observed["source_versions"].get(key)
    }
    raw_evidence_changes = _reference_delta(expected["raw_evidence"], observed["raw_evidence"])
    expected_duration, observed_duration = _duration(expected), _duration(observed)
    duration_delta = None if expected_duration is None or observed_duration is None else observed_duration - expected_duration

    material_drift = bool(node_changes or expected_unmatched_nodes or observed_unmatched_nodes or edge_changes
                          or expected_unmatched_edges or observed_unmatched_edges or source_version_changes)
    evidence_identity_drift = bool(raw_evidence_changes["added"] or raw_evidence_changes["removed"])
    categories = _changed_categories(node_changes, edge_changes, source_version_changes)
    if expected_unmatched_nodes or observed_unmatched_nodes or expected_unmatched_edges or observed_unmatched_edges:
        categories = sorted(set(categories) | {"execution_graph"})

    report = {
        "schema": SCHEMA,
        "comparison_id": comparison_id,
        "expected": {"record_id": expected["record_id"], "record_sha256": expected["record_sha256"]},
        "observed": {"record_id": observed["record_id"], "record_sha256": observed["record_sha256"]},
        "matching": {
            "node_strategy": "explicit-one-to-one-then-exact-id",
            "edge_strategy": "explicit-one-to-one-then-exact-id",
            "explicit_node_matches": dict(sorted(explicit_nodes.items())),
            "explicit_edge_matches": dict(sorted(explicit_edges.items())),
            "matched_nodes": [{"expected": key, "observed": value} for key, value in sorted(matched_nodes.items())],
            "matched_edges": [{"expected": key, "observed": value} for key, value in sorted(matched_edges.items())],
            "semantic_matching_inferred": False,
        },
        "node_changes": node_changes,
        "unmatched_nodes": {"expected_only": expected_unmatched_nodes, "observed_only": observed_unmatched_nodes},
        "edge_changes": edge_changes,
        "unmatched_edges": {"expected_only": expected_unmatched_edges, "observed_only": observed_unmatched_edges},
        "source_version_changes": source_version_changes,
        "raw_evidence_reference_changes": raw_evidence_changes,
        "timing_observations": {
            "expected_started_at": expected["started_at"], "observed_started_at": observed["started_at"],
            "expected_ended_at": expected.get("ended_at"), "observed_ended_at": observed.get("ended_at"),
            "expected_duration_seconds": expected_duration, "observed_duration_seconds": observed_duration,
            "duration_delta_seconds": duration_delta, "node_timestamp_changes": node_timing,
        },
        "summary": {
            "matched_nodes": len(matched_nodes), "changed_matched_nodes": len(node_changes),
            "expected_only_nodes": len(expected_unmatched_nodes), "observed_only_nodes": len(observed_unmatched_nodes),
            "matched_edges": len(matched_edges), "changed_matched_edges": len(edge_changes),
            "expected_only_edges": len(expected_unmatched_edges), "observed_only_edges": len(observed_unmatched_edges),
            "source_version_changes": len(source_version_changes),
            "raw_evidence_added": len(raw_evidence_changes["added"]),
            "raw_evidence_removed": len(raw_evidence_changes["removed"]),
            "node_timestamp_changes": len(node_timing),
            "material_execution_drift_observed": material_drift,
            "evidence_identity_drift_observed": evidence_identity_drift,
            "changed_categories": categories,
        },
        "claims": {
            "expected_record_is_ground_truth": False,
            "semantic_matching_inferred": False,
            "semantic_equivalence_proven": False,
            "behavioral_regression_proven": False,
            "compromise_proven": False,
            "intent_change_proven": False,
            "causality_proven": False,
            "complete_context_captured": False,
            "private_reasoning_captured": False,
        },
    }
    report["report_sha256"] = aer.sha256_bytes(aer.canonical_bytes(report))
    validate_comparison(report, expected=expected, observed=observed)
    return report


def validate_comparison(report: dict[str, Any], *, expected: dict[str, Any] | None = None,
                        observed: dict[str, Any] | None = None) -> bool:
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError("unsupported differential execution schema")
    _text(report.get("comparison_id"), "comparison_id")
    for side in ("expected", "observed"):
        binding = report.get(side)
        if not isinstance(binding, dict) or not isinstance(binding.get("record_sha256"), str) or not aer.SHA256_RE.fullmatch(binding["record_sha256"]):
            raise ValueError(f"invalid {side} AER binding")
        _text(binding.get("record_id"), f"{side} record_id")
    if expected is not None:
        aer.validate_record(expected)
        if report["expected"] != {"record_id": expected["record_id"], "record_sha256": expected["record_sha256"]}:
            raise ValueError("expected AER binding mismatch")
    if observed is not None:
        aer.validate_record(observed)
        if report["observed"] != {"record_id": observed["record_id"], "record_sha256": observed["record_sha256"]}:
            raise ValueError("observed AER binding mismatch")
    for key in ("node_changes", "edge_changes"):
        if not isinstance(report.get(key), list) or len(report[key]) > MAX_CHANGES:
            raise ValueError(f"invalid {key}")
    for key in ("unmatched_nodes", "unmatched_edges", "source_version_changes", "raw_evidence_reference_changes",
                "timing_observations", "summary", "matching"):
        if not isinstance(report.get(key), dict):
            raise ValueError(f"invalid {key}")
    matching = report["matching"]
    if matching.get("semantic_matching_inferred") is not False:
        raise ValueError("semantic matching cannot be inferred")
    claims = report.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("comparison claims missing")
    for key in ("expected_record_is_ground_truth", "semantic_matching_inferred", "semantic_equivalence_proven",
                "behavioral_regression_proven", "compromise_proven", "intent_change_proven", "causality_proven",
                "complete_context_captured", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(report)
    digest = unsigned.pop("report_sha256", None)
    if not isinstance(digest, str) or not aer.SHA256_RE.fullmatch(digest):
        raise ValueError("missing/invalid differential execution report hash")
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("differential execution report hash mismatch")
    return True
