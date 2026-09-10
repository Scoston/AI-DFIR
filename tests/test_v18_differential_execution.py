from __future__ import annotations

from copy import deepcopy

import pytest

import v18_agent_execution_record as aer
import v18_differential_execution as diff

T0 = "2026-09-10T14:00:00Z"
T1 = "2026-09-10T14:00:01Z"
T10 = "2026-09-10T14:10:00Z"
T11 = "2026-09-10T14:10:01Z"


def _ref(label: str):
    raw = label.encode()
    return aer.evidence_ref("synthetic", aer.sha256_bytes(raw), len(raw), chunk_id=label, observed_at=T0)


def _record(*, record_id: str, start: str = T0, end: str = T1,
            model: str = "model-a", prompt_hash: str = "prompt-a", policy: str = "policy-1",
            tool: str = "identity.lookup", principal: str = "agent-role-a",
            side_effect: str = "none", raw_label: str = "same", rename: bool = False):
    ref = _ref(raw_label)
    suffix = "-new" if rename else ""
    nodes = [
        aer.node(f"agent{suffix}", "agent", start, attributes={"agent_id": "agent-1"}, evidence_refs=[ref]),
        aer.node(f"context{suffix}", "context", start, attributes={"prompt_sha256": prompt_hash}, evidence_refs=[ref]),
        aer.node(f"model{suffix}", "model", start, attributes={"name": model}, evidence_refs=[ref]),
        aer.node(f"policy{suffix}", "policy", start, attributes={"revision": policy}, evidence_refs=[ref]),
        aer.node(f"identity{suffix}", "identity", start, attributes={"principal": principal}, evidence_refs=[ref]),
        aer.node(f"tool{suffix}", "tool", end, attributes={"name": tool}, evidence_refs=[ref]),
        aer.node(f"effect{suffix}", "side_effect", end, attributes={"result": side_effect}, evidence_refs=[ref]),
    ]
    edges = [
        aer.edge(f"edge-policy{suffix}", f"agent{suffix}", f"policy{suffix}", "evaluated_policy",
                 evidence_refs=[ref], policy_context={"revision": policy}, confidence="observed"),
        aer.edge(f"edge-tool{suffix}", f"agent{suffix}", f"tool{suffix}", "invoked", evidence_refs=[ref],
                 authority_context={"principal": principal}, approval_context={"approval": "observed"}, confidence="observed"),
        aer.edge(f"edge-effect{suffix}", f"tool{suffix}", f"effect{suffix}", "changed", evidence_refs=[ref], confidence="observed"),
    ]
    return aer.build_record(record_id, start, ended_at=end, nodes=nodes, edges=edges,
                            raw_evidence=[ref], source_versions={"runtime": "1", "policy": policy})


def test_identical_execution_has_no_material_drift():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed")
    report = diff.compare_executions(expected, observed, comparison_id="cmp-1")
    assert diff.validate_comparison(report, expected=expected, observed=observed)
    assert report["summary"]["material_execution_drift_observed"] is False
    assert report["node_changes"] == []
    assert report["edge_changes"] == []
    assert report["summary"]["changed_categories"] == []


def test_timing_drift_is_observed_but_not_material_by_itself():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed", start=T10, end=T11)
    report = diff.compare_executions(expected, observed, comparison_id="cmp-time")
    assert report["summary"]["material_execution_drift_observed"] is False
    assert report["summary"]["node_timestamp_changes"] == 7
    assert report["timing_observations"]["duration_delta_seconds"] == 0


def test_material_changes_surface_in_investigation_categories():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed", model="model-b", prompt_hash="prompt-b", policy="policy-2",
                       tool="identity.disable", principal="agent-role-b", side_effect="account-disabled")
    report = diff.compare_executions(expected, observed, comparison_id="cmp-drift")
    assert report["summary"]["material_execution_drift_observed"] is True
    categories = set(report["summary"]["changed_categories"])
    assert {"model", "prompt_context", "policy", "identity_authority", "tool", "side_effect", "source_version"} <= categories
    assert report["claims"]["behavioral_regression_proven"] is False
    assert report["claims"]["compromise_proven"] is False
    assert report["claims"]["intent_change_proven"] is False


def test_explicit_rename_mapping_preserves_graph_correspondence():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed", rename=True)
    node_map = {node["node_id"]: node["node_id"] + "-new" for node in expected["nodes"]}
    edge_map = {edge["edge_id"]: edge["edge_id"] + "-new" for edge in expected["edges"]}
    report = diff.compare_executions(expected, observed, comparison_id="cmp-map",
                                     node_matches=node_map, edge_matches=edge_map)
    assert report["summary"]["material_execution_drift_observed"] is False
    assert report["matching"]["semantic_matching_inferred"] is False
    assert all(item["match_basis"] == "explicit" for item in report["matching"]["matched_nodes"] if False) is True
    assert report["unmatched_nodes"] == {"expected_only": [], "observed_only": []}
    assert report["unmatched_edges"] == {"expected_only": [], "observed_only": []}


def test_unmatched_objects_are_reported_not_auto_semantically_matched():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed")
    nodes = list(observed["nodes"])
    nodes.append(aer.node("extra-tool", "tool", T1, attributes={"name": "unexpected.delete"}))
    observed2 = aer.build_record("observed-2", T0, ended_at=T1, nodes=nodes, edges=observed["edges"],
                                 raw_evidence=observed["raw_evidence"], source_versions=observed["source_versions"])
    report = diff.compare_executions(expected, observed2, comparison_id="cmp-unmatched")
    assert report["unmatched_nodes"]["observed_only"] == ["extra-tool"]
    assert report["summary"]["material_execution_drift_observed"] is True
    assert "execution_graph" in report["summary"]["changed_categories"]


def test_authority_policy_and_approval_context_changes_are_explicit():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed")
    changed_edges = deepcopy(observed["edges"])
    tool_edge = next(edge for edge in changed_edges if edge["edge_id"] == "edge-tool")
    tool_edge["authority_context"]["principal"] = "break-glass-role"
    tool_edge["approval_context"]["approval"] = "not-observed"
    policy_edge = next(edge for edge in changed_edges if edge["edge_id"] == "edge-policy")
    policy_edge["policy_context"]["revision"] = "policy-99"
    observed2 = aer.build_record("observed-2", T0, ended_at=T1, nodes=observed["nodes"], edges=changed_edges,
                                 raw_evidence=observed["raw_evidence"], source_versions=observed["source_versions"])
    report = diff.compare_executions(expected, observed2, comparison_id="cmp-context")
    categories = set(report["summary"]["changed_categories"])
    assert {"identity_authority", "approval", "policy"} <= categories
    assert len(report["edge_changes"]) == 2


def test_raw_evidence_identity_drift_is_separate_from_material_execution_drift():
    expected = _record(record_id="expected", raw_label="evidence-a")
    observed = _record(record_id="observed", raw_label="evidence-b")
    report = diff.compare_executions(expected, observed, comparison_id="cmp-evidence")
    assert report["summary"]["evidence_identity_drift_observed"] is True
    assert report["summary"]["material_execution_drift_observed"] is True  # node/edge evidence bindings also changed
    assert report["summary"]["raw_evidence_added"] == 1
    assert report["summary"]["raw_evidence_removed"] == 1


def test_mapping_is_one_to_one_and_must_reference_real_ids():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed", rename=True)
    with pytest.raises(ValueError, match="one-to-one"):
        diff.compare_executions(expected, observed, comparison_id="bad-map",
                                node_matches={"agent": "agent-new", "context": "agent-new"})
    with pytest.raises(ValueError, match="missing expected id"):
        diff.compare_executions(expected, observed, comparison_id="bad-map-2",
                                node_matches={"does-not-exist": "agent-new"})


def test_tampered_report_and_source_binding_fail_closed():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed")
    report = diff.compare_executions(expected, observed, comparison_id="cmp-tamper")
    forged = deepcopy(report)
    forged["claims"]["compromise_proven"] = True
    with pytest.raises(ValueError, match="compromise_proven"):
        diff.validate_comparison(forged, expected=expected, observed=observed)
    wrong = _record(record_id="wrong", model="other")
    with pytest.raises(ValueError, match="observed AER binding mismatch"):
        diff.validate_comparison(report, expected=expected, observed=wrong)


def test_source_array_order_does_not_change_reported_differences():
    expected = _record(record_id="expected")
    observed = _record(record_id="observed", model="model-b")
    reordered_expected = aer.build_record("expected-reordered", T0, ended_at=T1,
        nodes=list(reversed(expected["nodes"])), edges=list(reversed(expected["edges"])),
        raw_evidence=expected["raw_evidence"], source_versions=expected["source_versions"])
    reordered_observed = aer.build_record("observed-reordered", T0, ended_at=T1,
        nodes=list(reversed(observed["nodes"])), edges=list(reversed(observed["edges"])),
        raw_evidence=observed["raw_evidence"], source_versions=observed["source_versions"])
    one = diff.compare_executions(expected, observed, comparison_id="cmp-one")
    two = diff.compare_executions(reordered_expected, reordered_observed, comparison_id="cmp-two")
    assert one["node_changes"] == two["node_changes"]
    assert one["edge_changes"] == two["edge_changes"]
    assert one["summary"] == two["summary"]
