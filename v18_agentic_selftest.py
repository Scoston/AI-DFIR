#!/usr/bin/env python3
"""Engine-independent v1.8 agentic forensics acceptance self-test."""
from __future__ import annotations

import base64
import json

import v18_agent_execution_record as aer
import v18_agentic_detections as detect
import v18_ai_ml_bom as aibom
import v18_a2a_forensics as a2a
import v18_credential_lineage as credential_lineage
import v18_mcp_forensics as mcp
import v18_otel_genai as otel
import v18_otlp_envelope as otlp
import v18_rag_memory as provenance
import v18_runtime_reconstruction as reconstruction

T = "2026-09-09T18:00:00Z"
T2 = "2026-09-09T18:00:01Z"


def _b64(value: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()


def _jwt(claims: dict) -> bytes:
    header = {"alg": "RS256", "typ": "at+jwt", "kid": "selftest-kid"}
    return f"{_b64(header)}.{_b64(claims)}.c2ln".encode()


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

    a2a_request = json.dumps({
        "jsonrpc": "2.0", "id": "a2a-1", "method": "SendMessage",
        "params": {"message": {"messageId": "msg-a2a-1", "contextId": "ctx-a2a-1",
                                "role": "ROLE_USER", "parts": [{"text": "investigate"}]}}
    }, separators=(",", ":")).encode()
    a2a_response = json.dumps({
        "jsonrpc": "2.0", "id": "a2a-1",
        "result": {"task": {"id": "task-a2a-1", "contextId": "ctx-a2a-1",
                            "status": {"state": "TASK_STATE_COMPLETED"},
                            "artifacts": [{"artifactId": "artifact-a2a-1", "parts": [{"text": "done"}]}]}}
    }, separators=(",", ":")).encode()
    a2a_exchange = a2a.capture_exchange(
        binding="JSONRPC", http_method="POST", path="/rpc",
        request_headers={"Content-Type": "application/json", "A2A-Version": "1.0",
                         "Authorization": "Bearer synthetic-selftest-secret"},
        request_body=a2a_request, response_status=200,
        response_headers={"Content-Type": "application/json"}, response_body=a2a_response,
        observed_at=T, client_agent_id="agent-client", server_agent_id="agent-server",
    )
    a2a_bundle = a2a.exchanges_to_aer([a2a_exchange], record_id="case-001/a2a")
    assert a2a.validate_exchange(a2a_exchange)
    assert a2a.validate_aer_binding(a2a_bundle)
    assert a2a_exchange["operation"] == "SendMessage"
    assert "authorization" not in a2a_exchange["request_headers"]["safe_values"]
    assert {"task", "message", "artifact"} <= {n["kind"] for n in a2a_bundle["aer"]["nodes"]}
    assert a2a_bundle["claims"]["delegated_authority_proven"] is False

    subject_token = _jwt({
        "iss": "https://synthetic-idp.example", "sub": "human-1", "aud": "broker",
        "client_id": "human-client", "scope": "read investigate", "iat": 1789045200,
        "exp": 1789056000, "jti": "subject-jti",
    })
    actor_token = _jwt({
        "iss": "https://synthetic-idp.example", "sub": "agent-1", "aud": "identity-api",
        "client_id": "agent-client", "scope": "read investigate disable", "iat": 1789045201,
        "exp": 1789056001, "jti": "actor-jti", "act": {"sub": "human-1", "client_id": "human-client"},
    })
    credential_records = [
        credential_lineage.credential_observation("subject-token", subject_token, credential_type="oauth-access-token",
                                                  observed_at=T, scheme="Bearer", metadata={"synthetic": True}),
        credential_lineage.credential_observation("actor-token", actor_token, credential_type="oauth-access-token",
                                                  observed_at=T2, scheme="Bearer", metadata={"synthetic": True}),
    ]
    principal_records = [
        credential_lineage.principal("human-1", kind="human", observed_at=T, provider="synthetic-idp"),
        credential_lineage.principal("agent-1", kind="agent", observed_at=T2, provider="synthetic-runtime"),
    ]
    jwt_records = [
        credential_lineage.jwt_structure(subject_token, observed_at=T, credential_id="subject-token"),
        credential_lineage.jwt_structure(actor_token, observed_at=T2, credential_id="actor-token"),
    ]
    hop = credential_lineage.delegation_hop(
        "exchange-1", mechanism="oauth-token-exchange", observed_at=T2,
        input_credential_id="subject-token", output_credential_id="actor-token",
        source_principal_id="human-1", target_principal_id="agent-1",
        issuer="https://synthetic-idp.example", audience="identity-api",
        scopes=["read", "investigate", "disable"], authorization_decision="allowed",
        evidence_refs=[ref], policy_context={"revision": "selftest"}, approval_context={"approval": "observed"},
    )
    shown = credential_lineage.presentation(
        "presentation-1", credential_id="actor-token", presenter_principal_id="agent-1",
        observed_at=T2, target="identity-api:/users/alice:disable", audience="identity-api",
        scopes=["disable"], authorization_decision="allowed", evidence_refs=[ref],
    )
    credential_report = credential_lineage.build_lineage(
        lineage_id="case-001/credential-lineage", credentials=credential_records, principals=principal_records,
        hops=[hop], presentations=[shown], jwt_structures=jwt_records,
    )
    credential_bundle = credential_lineage.to_aer(credential_report, record_id="case-001/credential-lineage-aer")
    assert credential_lineage.validate_lineage(credential_report)
    assert credential_lineage.validate_aer_binding(credential_bundle, report=credential_report)
    assert credential_report["diagnostics"]["scope_changes"][0]["scope_expansion_observed"] is True
    assert credential_bundle["claims"]["mere_presentation_treated_as_delegation"] is False
    assert actor_token.decode() not in json.dumps(credential_report, sort_keys=True)
    assert all(value is False for value in jwt_records[1]["verification"].values())

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

    forged = dict(record)
    forged["record_id"] = "forged"
    rejected = False
    try:
        aer.validate_record(forged)
    except ValueError:
        rejected = True
    assert rejected

    print(json.dumps({"status": "PASS", "aer_nodes": len(nodes), "aer_edges": len(edges),
                      "mcp_offline_replay": True, "retrieval_documents": 1, "memory_events": 1,
                      "otel_raw_preserved": True, "otel_aer_spans": 2, "otlp_envelope_spans": 2,
                      "otlp_log_records": 1, "otlp_trace_log_matches": 1, "a2a_exchanges": 1,
                      "a2a_protocol_objects": 3, "a2a_credential_values_retained": False,
                      "credential_lineage_hops": 1, "credential_lineage_presentations": 1,
                      "credential_values_retained": False, "presentation_inflated_to_delegation": False,
                      "agentic_findings": 1, "aibom_components": 2, "aibom_drift_detected": True,
                      "private_reasoning_captured": False}, sort_keys=True))


if __name__ == "__main__":
    main()
