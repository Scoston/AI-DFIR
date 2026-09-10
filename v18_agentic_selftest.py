#!/usr/bin/env python3
"""Engine-independent v1.8 agentic forensics acceptance self-test."""
from __future__ import annotations

import json

import v18_agent_execution_record as aer
import v18_agentic_detections as detect
import v18_ai_ml_bom as aibom
import v18_mcp_forensics as mcp
import v18_otel_genai as otel
import v18_otlp_envelope as otlp
import v18_rag_memory as provenance
import v18_runtime_reconstruction as reconstruction

T = "2026-09-09T18:00:00Z"
T2 = "2026-09-09T18:00:01Z"


def main() -> None:
    raw = b'{"event":"tool-call"}'
    ref = aer.evidence_ref("synthetic-event", aer.sha256_bytes(raw), len(raw), chunk_id="chunk-001", observed_at=T)
    nodes = [
        aer.node("human-1", "human", T, attributes={"request": "investigate"}, evidence_refs=[ref]),
        aer.node("agent-1", "agent", T, attributes={"tool_policy_violation": True}, evidence_refs=[ref]),
        aer.node("tool-1", "tool", T, attributes={"name": "disable-account"}, evidence_refs=[ref]),
    ]
    edges = [aer.edge("edge-1", "agent-1", "tool-1", "invoked", evidence_refs=[ref],
                      authority_context={"principal": "delegated-user"}, confidence="observed")]
    record = aer.build_record("case-001/run-001", T, nodes=nodes, edges=edges,
                              raw_evidence=[ref], source_versions={"mcp": mcp.MCP_SPEC_VERSION})
    assert aer.validate_record(record)

    request = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"disable-account","arguments":{"user":"alice"}}}'
    response = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}'
    exchange = mcp.capture_exchange(request, response,
        request_headers={"MCP-Protocol-Version": mcp.MCP_SPEC_VERSION, "Mcp-Method": "tools/call", "Mcp-Name": "disable-account"},
        response_headers={"Content-Type": "application/json"}, observed_at=T)
    replay = mcp.replay_offline(exchange)
    assert replay["network_performed"] is False and replay["tool_executed"] is False

    doc = provenance.document("doc-1", "chunk-001", content=b"authoritative source", score=0.98, rank=0)
    retrieval = provenance.retrieval(b"who changed the account?", observed_at=T, index_id="idx-1", index_revision="rev-42",
        embedding_model={"name": "embed-model", "version": "1"}, returned_documents=[doc])
    assert provenance.validate_retrieval(retrieval)
    memory = provenance.memory_event("write", memory_id="mem-1", observed_at=T, source_execution_id=record["record_id"],
        before=b"old", input_content=b"new", after=b"new")
    assert provenance.validate_memory(memory)

    span = {"traceId": "abc", "spanId": "def", "name": "agent-run", "attributes": {
        "gen_ai.agent.id": "agent-1", "gen_ai.operation.name": "invoke_agent",
        "gen_ai.retrieval.query.text": "who changed the account?", "gen_ai.tool.name": "disable-account",
        "custom.attribute": "preserved-only-in-raw"}}
    adapted = otel.adapt_span(span, semantic_conventions_version="operator-declared", observed_at=T)
    assert otel.validate(adapted)
    assert "custom.attribute" not in adapted["normalized_genai"]
    child = otel.adapt_span({"traceId": "abc", "spanId": "ghi", "parentSpanId": "def", "name": "tool-run",
                             "attributes": {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "disable-account"}},
                            semantic_conventions_version="operator-declared", observed_at=T2)
    rebuilt = reconstruction.reconstruct_trace([child, adapted], record_id="case-001/otel-trace-abc")
    assert reconstruction.validate_reconstruction(rebuilt)
    assert rebuilt["diagnostics"]["span_count"] == 2
    assert rebuilt["claims"]["intent_causality_proven"] is False

    otlp_trace_id = "0123456789abcdef0123456789abcdef"
    otlp_root = "0123456789abcdef"
    otlp_child = "fedcba9876543210"
    trace_envelope = {
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agent-service"}}]},
            "scopeSpans": [{
                "scope": {"name": "agent.instrumentation", "version": "1.8"},
                "spans": [
                    {"traceId": otlp_trace_id, "spanId": otlp_root, "name": "invoke-agent",
                     "attributes": [
                         {"key": "gen_ai.agent.id", "value": {"stringValue": "agent-1"}},
                         {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
                     ]},
                    {"traceId": otlp_trace_id, "spanId": otlp_child, "parentSpanId": otlp_root,
                     "name": "execute-tool", "attributes": [
                         {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
                         {"key": "gen_ai.tool.name", "value": {"stringValue": "disable-account"}},
                     ]},
                ],
            }],
        }],
    }
    log_envelope = {
        "resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agent-service"}}]},
            "scopeLogs": [{"scope": {"name": "agent.logs"}, "logRecords": [
                {"timeUnixNano": "1", "traceId": otlp_trace_id, "spanId": otlp_child,
                 "body": {"stringValue": "tool completed"}},
            ]}],
        }],
    }
    trace_import = otlp.import_trace_envelope(trace_envelope, semantic_conventions_version="operator-declared", observed_at=T)
    log_import = otlp.import_log_envelope(log_envelope, observed_at=T)
    envelope_rebuilt = otlp.reconstruct_imported_trace(trace_import, trace_id=otlp_trace_id,
                                                        record_id="case-001/otlp-trace")
    trace_log = otlp.correlate_trace_logs(trace_import, log_import)
    assert otlp.validate_trace_import(trace_import)
    assert otlp.validate_log_import(log_import)
    assert otlp.validate_imported_reconstruction(envelope_rebuilt, trace_import=trace_import)
    assert otlp.validate_trace_log_correlation(trace_log, trace_import=trace_import, log_import=log_import)
    assert trace_log["summary"]["matched_trace_and_span"] == 1
    assert trace_log["claims"]["business_causality_proven"] is False

    findings = detect.evaluate(record)
    assert [x["risk_id"] for x in findings["findings"]] == ["ASI02"]
    assert findings["claims"]["attack_proven"] is False

    model = aibom.component("model:primary", "model", "example-model", version="1")
    server = aibom.component("mcp:identity", "mcp-server", "identity-server", version="2026.09")
    bom = aibom.build("system-1", observed_at=T, components=[model, server], dependencies=[("model:primary", "mcp:identity")])
    assert aibom.validate(bom)
    cdx = aibom.to_cyclonedx_1_7(bom)
    assert cdx["specVersion"] == "1.7" and len(cdx["components"]) == 2
    observed_model = aibom.component("model:primary", "model", "example-model", version="2")
    observed_bom = aibom.build("system-1", observed_at=T2, components=[observed_model, server],
                               dependencies=[("model:primary", "mcp:identity")])
    drift = aibom.compare(bom, observed_bom)
    assert drift["summary"]["drift_detected"] is True
    assert drift["component_changes"][0]["changed_fields"] == ["version"]
    assert drift["claims"]["compromise_proven"] is False

    forged = dict(record); forged["record_id"] = "forged"
    rejected = False
    try:
        aer.validate_record(forged)
    except ValueError:
        rejected = True
    assert rejected

    print(json.dumps({"status": "PASS", "aer_nodes": len(nodes), "aer_edges": len(edges),
                      "mcp_offline_replay": True, "retrieval_documents": 1, "memory_events": 1,
                      "otel_raw_preserved": True, "otel_aer_spans": 2, "otlp_envelope_spans": 2,
                      "otlp_log_records": 1, "otlp_trace_log_matches": 1, "agentic_findings": 1,
                      "aibom_components": 2, "aibom_drift_detected": True,
                      "private_reasoning_captured": False}, sort_keys=True))


if __name__ == "__main__":
    main()
