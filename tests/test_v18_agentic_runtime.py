from __future__ import annotations

import copy

import pytest

import v18_agent_execution_record as aer
import v18_agentic_detections as detect
import v18_ai_ml_bom as aibom
import v18_mcp_forensics as mcp
import v18_otel_genai as otel
import v18_rag_memory as provenance

T = "2026-09-09T18:00:00Z"


def sample_record(signal: str | None = None):
    raw = b"evidence"
    ref = aer.evidence_ref("fixture", aer.sha256_bytes(raw), len(raw), chunk_id="chunk-7", observed_at=T)
    attrs = {signal: True} if signal else {}
    nodes = [aer.node("agent", "agent", T, attributes=attrs, evidence_refs=[ref]),
             aer.node("tool", "tool", T, attributes={"name": "identity"}, evidence_refs=[ref])]
    edges = [aer.edge("e1", "agent", "tool", "invoked", evidence_refs=[ref], confidence="observed")]
    return aer.build_record("case/run", T, nodes=nodes, edges=edges, raw_evidence=[ref])


def test_aer_hash_and_edge_binding():
    record = sample_record()
    assert aer.validate_record(record)
    forged = copy.deepcopy(record)
    forged["edges"][0]["target_node"] = "missing"
    with pytest.raises(ValueError):
        aer.validate_record(forged)


def test_aer_never_claims_private_reasoning():
    with pytest.raises(ValueError):
        aer.build_record("case/run", T, claims={"private_reasoning_captured": True})


def test_mcp_capture_preserves_exact_bytes_and_offline_replay():
    req = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}'
    res = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
    record = mcp.capture_exchange(req, res, request_headers={"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "search"}, response_headers={}, observed_at=T)
    assert mcp.validate_exchange(record)
    replay = mcp.replay_offline(record)
    assert replay["network_performed"] is False
    assert replay["tool_executed"] is False
    assert record["request"]["sha256"] == aer.sha256_bytes(req)


def test_mcp_detects_header_body_divergence():
    req = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"}}'
    res = b'{"jsonrpc":"2.0","id":1,"result":{}}'
    record = mcp.capture_exchange(req, res, request_headers={"Mcp-Method": "resources/read", "Mcp-Name": "different"}, response_headers={}, observed_at=T)
    assert len(record["header_body_divergence"]) == 2


def test_rag_chunk_and_memory_custody():
    doc = provenance.document("doc", "chunk-1", content=b"source", score=0.4, rank=1)
    retrieval = provenance.retrieval(b"query", observed_at=T, index_id="index", index_revision="r1", embedding_model={"name": "embed", "version": "1"}, returned_documents=[doc])
    assert provenance.validate_retrieval(retrieval)
    assert retrieval["returned_documents"][0]["chunk_id"] == "chunk-1"
    memory = provenance.memory_event("write", memory_id="m1", observed_at=T, source_execution_id="case/run", before=b"a", input_content=b"b", after=b"b")
    assert provenance.validate_memory(memory)
    forged = copy.deepcopy(memory); forged["after"]["size"] = 999
    with pytest.raises(ValueError):
        provenance.validate_memory(forged)


def test_otel_adapter_preserves_raw_and_declared_version():
    span = {"traceId": "t", "spanId": "s", "name": "run", "attributes": [{"key": "gen_ai.agent.id", "value": {"stringValue": "a1"}}, {"key": "vendor.private", "value": {"stringValue": "retained"}}]}
    record = otel.adapt_span(span, semantic_conventions_version="test-version", observed_at=T)
    assert otel.validate(record)
    assert record["semantic_conventions_version"] == "test-version"
    assert record["normalized_genai"]["gen_ai.agent.id"] == "a1"
    assert "vendor.private" not in record["normalized_genai"]


def test_agentic_detection_requires_explicit_observed_signal():
    empty = detect.evaluate(sample_record())
    assert empty["findings"] == []
    hit = detect.evaluate(sample_record("memory_integrity_failed"))
    assert hit["findings"][0]["risk_id"] == "ASI06"
    assert hit["claims"]["attack_proven"] is False


def test_ai_ml_bom_dependencies_and_projection():
    model = aibom.component("model", "model", "m", version="1")
    tool = aibom.component("tool", "tool", "t", version="2")
    record = aibom.build("sys", observed_at=T, components=[model, tool], dependencies=[("model", "tool")])
    cdx = aibom.to_cyclonedx_1_7(record)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.7"
    assert {x["bom-ref"] for x in cdx["components"]} == {"model", "tool"}
    assert record["claims"]["cyclonedx_conformance_verified"] is False
