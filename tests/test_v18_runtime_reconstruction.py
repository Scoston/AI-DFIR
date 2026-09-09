from __future__ import annotations

import copy

import pytest

import v18_agent_execution_record as aer
import v18_otel_genai as otel
import v18_runtime_reconstruction as recon

T0 = "2026-09-09T18:00:00Z"
T1 = "2026-09-09T18:00:01Z"
T2 = "2026-09-09T18:00:02Z"


def span(span_id: str | None, *, parent: str | None = None, observed_at: str = T0,
         trace_id: str = "trace-1", attrs: dict | None = None, name: str = "span"):
    raw = {"traceId": trace_id, "name": name, "attributes": attrs or {}}
    if span_id is not None:
        raw["spanId"] = span_id
    if parent is not None:
        raw["parentSpanId"] = parent
    return otel.adapt_span(raw, semantic_conventions_version="test-semconv", observed_at=observed_at)


def test_reconstruct_agent_retrieval_tool_chain_without_causality_inference():
    root = span("root", observed_at=T0, attrs={
        "gen_ai.agent.id": "agent-1", "gen_ai.operation.name": "invoke_agent",
        "gen_ai.request.model": "model-a", "gen_ai.provider.name": "provider-a",
    })
    retrieval = span("retrieve", parent="root", observed_at=T1, attrs={
        "gen_ai.operation.name": "retrieval", "gen_ai.retrieval.query.text": "account owner",
        "gen_ai.retrieval.documents": [{"id": "chunk-1"}],
    })
    tool = span("tool", parent="retrieve", observed_at=T2, attrs={
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "identity.lookup",
        "gen_ai.tool.type": "function",
    })
    bundle = recon.reconstruct_trace([tool, root, retrieval], record_id="case/run")
    assert recon.validate_reconstruction(bundle)
    record = bundle["aer"]
    assert record["started_at"] == T0 and record["ended_at"] == T2
    assert record["claims"]["complete_context_captured"] is False
    assert bundle["claims"]["business_causality_proven"] is False
    assert bundle["diagnostics"]["causal_links_inferred"] is False
    kinds = {node["kind"] for node in record["nodes"]}
    assert {"agent", "workflow", "retrieval", "tool", "model"}.issubset(kinds)
    parent_edges = [edge for edge in record["edges"] if edge["edge_id"].startswith("edge:otel-parent:")]
    assert len(parent_edges) == 2
    assert all(edge["relationship"] == "correlated_with" for edge in parent_edges)
    assert all("business_causality" in edge["unknown_fields"] for edge in parent_edges)


def test_input_order_does_not_change_aer_or_bundle_hash():
    one = span("a", observed_at=T0, attrs={"gen_ai.agent.id": "agent"})
    two = span("b", parent="a", observed_at=T1, attrs={"gen_ai.tool.name": "search"})
    left = recon.reconstruct_trace([one, two], record_id="case/run")
    right = recon.reconstruct_trace([two, one], record_id="case/run")
    assert left["aer"]["record_sha256"] == right["aer"]["record_sha256"]
    assert left["bundle_sha256"] == right["bundle_sha256"]


def test_orphan_parent_is_explicit_and_not_fabricated():
    child = span("child", parent="missing-parent", attrs={"gen_ai.operation.name": "invoke_agent"})
    bundle = recon.reconstruct_trace([child], record_id="case/run")
    assert bundle["diagnostics"]["orphan_parent_span_ids"] == [
        {"span_id": "child", "missing_parent_span_id": "missing-parent"}
    ]
    assert not any(edge["edge_id"].startswith("edge:otel-parent:") for edge in bundle["aer"]["edges"])


def test_missing_span_id_is_retained_as_unknown_node():
    item = span(None, attrs={"vendor.only": "x"})
    bundle = recon.reconstruct_trace([item], record_id="case/run")
    assert bundle["diagnostics"]["missing_span_id_record_sha256"] == [item["record_sha256"]]
    assert len(bundle["diagnostics"]["unmapped_span_ids"]) == 1
    assert bundle["aer"]["nodes"][0]["kind"] == "unknown"
    assert bundle["aer"]["raw_evidence"][0]["sha256"] == item["raw_span"]["sha256"]


def test_duplicate_span_id_fails_closed():
    one = span("dup", attrs={"gen_ai.agent.id": "a"})
    two = span("dup", observed_at=T1, attrs={"gen_ai.agent.id": "b"})
    with pytest.raises(ValueError, match="duplicate span_id"):
        recon.reconstruct_trace([one, two], record_id="case/run")


def test_parent_cycle_fails_closed():
    one = span("a", parent="b")
    two = span("b", parent="a", observed_at=T1)
    with pytest.raises(ValueError, match="cyclic parent_span_id graph"):
        recon.reconstruct_trace([one, two], record_id="case/run")


def test_multiple_traces_are_not_silently_combined():
    one = span("a", trace_id="trace-a")
    two = span("b", trace_id="trace-b")
    with pytest.raises(ValueError, match="exactly one non-empty trace_id"):
        recon.reconstruct_trace([one, two], record_id="case/run")


def test_forged_bundle_is_rejected():
    item = span("a", attrs={"gen_ai.agent.id": "a"})
    bundle = recon.reconstruct_trace([item], record_id="case/run")
    forged = copy.deepcopy(bundle)
    forged["claims"]["intent_causality_proven"] = True
    with pytest.raises(ValueError, match="intent_causality_proven"):
        recon.validate_reconstruction(forged)


def test_each_source_span_is_bound_as_raw_evidence():
    one = span("a", attrs={"gen_ai.agent.id": "a"})
    two = span("b", parent="a", observed_at=T1, attrs={"gen_ai.tool.name": "search"})
    bundle = recon.reconstruct_trace([one, two], record_id="case/run")
    hashes = {ref["sha256"] for ref in bundle["aer"]["raw_evidence"]}
    assert hashes == {one["raw_span"]["sha256"], two["raw_span"]["sha256"]}
    assert aer.validate_record(bundle["aer"])
