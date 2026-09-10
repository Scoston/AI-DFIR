from __future__ import annotations

import copy
import json

import pytest

import v18_agent_execution_record as aer
import v18_a2a_forensics as a2a

T = "2026-09-10T12:30:00Z"
T2 = "2026-09-10T12:30:01Z"


def _headers(version: str = "1.0") -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "A2A-Version": version,
        "A2A-Extensions": "https://example.test/ext/a, https://example.test/ext/b",
        "Authorization": "Bearer very-secret-token",
    }


def _jsonrpc_request() -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "msg-1",
                "contextId": "ctx-1",
                "role": "ROLE_USER",
                "parts": [{"text": "Investigate account activity"}],
            }
        },
    }, separators=(",", ":")).encode()


def _jsonrpc_response() -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "task": {
                "id": "task-1",
                "contextId": "ctx-1",
                "status": {"state": "TASK_STATE_COMPLETED"},
                "artifacts": [{
                    "artifactId": "artifact-1",
                    "name": "result",
                    "parts": [{"text": "Account reviewed"}],
                }],
                "history": [{
                    "messageId": "msg-2",
                    "contextId": "ctx-1",
                    "taskId": "task-1",
                    "role": "ROLE_AGENT",
                    "parts": [{"text": "Investigation complete"}],
                }],
            }
        },
    }, separators=(",", ":")).encode()


def _exchange(binding: str = "JSONRPC", *, at: str = T) -> dict:
    if binding == "JSONRPC":
        request = _jsonrpc_request()
        response = _jsonrpc_response()
        path = "/rpc"
        content_type = "application/json"
    else:
        request = json.dumps({
            "message": {
                "messageId": "msg-http-1",
                "contextId": "ctx-http-1",
                "role": "ROLE_USER",
                "parts": [{"text": "hello"}],
            }
        }, separators=(",", ":")).encode()
        response = json.dumps({
            "task": {
                "id": "task-http-1",
                "contextId": "ctx-http-1",
                "status": {"state": "TASK_STATE_WORKING"},
            }
        }, separators=(",", ":")).encode()
        path = "/message:send"
        content_type = "application/a2a+json"
    headers = _headers()
    headers["Content-Type"] = content_type
    return a2a.capture_exchange(
        binding=binding,
        http_method="POST",
        path=path,
        request_headers=headers,
        request_body=request,
        response_status=200,
        response_headers={"Content-Type": content_type},
        response_body=response,
        observed_at=at,
        client_agent_id="client-agent",
        server_agent_id="server-agent",
        agent_card_sha256="a" * 64,
    )


def test_jsonrpc_capture_redacts_reusable_credential_header() -> None:
    record = _exchange()
    assert a2a.validate_exchange(record)
    assert record["operation"] == "SendMessage"
    assert record["request_protocol"]["method_is_known_1_0"] is True
    assert record["service_parameters"]["version"]["effective_major_minor"] == "1.0"
    assert record["service_parameters"]["extensions"] == [
        "https://example.test/ext/a", "https://example.test/ext/b"
    ]
    assert "authorization" not in record["request_headers"]["safe_values"]
    auth = record["request_headers"]["sensitive_fingerprints"]["authorization"][0]
    assert auth["scheme"] == "Bearer"
    assert auth["sha256"] == aer.sha256_bytes(b"Bearer very-secret-token")
    assert record["claims"]["credential_header_values_retained"] is False


def test_missing_version_is_recorded_as_legacy_default_not_v1() -> None:
    headers = _headers()
    headers.pop("A2A-Version")
    record = a2a.capture_exchange(
        binding="HTTP+JSON", http_method="POST", path="/message:send",
        request_headers=headers,
        request_body=b'{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]}}',
        response_status=200, response_headers={}, response_body=b'{}', observed_at=T,
        client_agent_id="c", server_agent_id="s",
    )
    version = record["service_parameters"]["version"]
    assert version["effective_major_minor"] == "0.3"
    assert version["matches_profile"] is False
    assert version["missing_for_1_0_client"] is True


def test_http_json_operation_mapping() -> None:
    record = _exchange("HTTP+JSON")
    assert record["operation"] == "SendMessage"
    assert record["binding"] == "HTTP+JSON"


@pytest.mark.parametrize("method,path,operation", [
    ("POST", "/message:stream", "SendStreamingMessage"),
    ("GET", "/tasks/task-1", "GetTask"),
    ("GET", "/tasks?contextId=c", "ListTasks"),
    ("POST", "/tasks/task-1:cancel", "CancelTask"),
    ("POST", "/tasks/task-1:subscribe", "SubscribeToTask"),
    ("GET", "/extendedAgentCard", "GetExtendedAgentCard"),
])
def test_http_operation_routes(method: str, path: str, operation: str) -> None:
    body = b'{}' if method == "POST" else b""
    record = a2a.capture_exchange(
        binding="HTTP+JSON", http_method=method, path=path,
        request_headers={"A2A-Version": "1.0"}, request_body=body,
        response_status=200, response_headers={}, response_body=b'{}',
        observed_at=T, client_agent_id="c", server_agent_id="s",
    )
    assert record["operation"] == operation


def test_duplicate_json_keys_fail_closed() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        a2a.capture_exchange(
            binding="HTTP+JSON", http_method="POST", path="/message:send",
            request_headers={"A2A-Version": "1.0"},
            request_body=b'{"message":1,"message":2}',
            response_status=200, response_headers={}, response_body=b'{}',
            observed_at=T, client_agent_id="c", server_agent_id="s",
        )


def test_tampered_exchange_hash_rejected() -> None:
    record = _exchange()
    forged = copy.deepcopy(record)
    forged["operation"] = "CancelTask"
    with pytest.raises(ValueError, match="record hash mismatch"):
        a2a.validate_exchange(forged)


def test_agent_card_observation_does_not_claim_jws_trust() -> None:
    card = {
        "name": "Synthetic Agent",
        "description": "test",
        "supportedInterfaces": [{
            "url": "https://agent.example.test/a2a",
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
        }],
        "version": "3.2.1",
        "capabilities": {"streaming": True},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "investigate", "name": "Investigate", "description": "test", "tags": ["dfir"]}],
        "signatures": [{"protected": "abc", "signature": "def"}],
    }
    observed = a2a.observe_agent_card(json.dumps(card).encode(), observed_at=T,
                                      source_locator="https://agent.example.test/.well-known/agent-card.json")
    assert observed["summary"]["skill_ids"] == ["investigate"]
    assert observed["summary"]["signature_count"] == 1
    assert observed["claims"]["card_signature_verified_by_this_module"] is False
    assert observed["claims"]["provider_trusted"] is False


def test_sse_stream_preserves_order_and_single_union_member() -> None:
    event1 = {"task": {"id": "task-1", "contextId": "ctx-1", "status": {"state": "TASK_STATE_WORKING"}}}
    event2 = {"statusUpdate": {"taskId": "task-1", "contextId": "ctx-1", "status": {"state": "TASK_STATE_COMPLETED"}}}
    raw = ("data: " + json.dumps(event1, separators=(",", ":")) + "\n\n" +
           "data: " + json.dumps(event2, separators=(",", ":")) + "\n\n").encode()
    stream = a2a.capture_sse_stream(raw, binding="HTTP+JSON", observed_at=T)
    assert [item["event_type"] for item in stream["events"]] == ["task", "statusUpdate"]
    assert stream["raw_stream"]["sha256"] == aer.sha256_bytes(raw)
    assert stream["claims"]["delivery_complete"] is False


def test_sse_invalid_union_fails_closed() -> None:
    raw = b'data: {"task":{},"message":{}}\n\n'
    with pytest.raises(ValueError, match="exactly one"):
        a2a.capture_sse_stream(raw, binding="HTTP+JSON", observed_at=T)


def test_exchanges_to_aer_creates_first_class_protocol_objects() -> None:
    one = _exchange(at=T)
    two = a2a.capture_exchange(
        binding="HTTP+JSON", http_method="POST", path="/message:send",
        request_headers={"A2A-Version": "1.0"},
        request_body=json.dumps({
            "message": {"messageId": "msg-3", "contextId": "ctx-1", "taskId": "task-1",
                        "role": "ROLE_USER", "parts": [{"text": "continue"}]}
        }).encode(),
        response_status=200, response_headers={"Content-Type": "application/a2a+json"},
        response_body=json.dumps({
            "task": {"id": "task-1", "contextId": "ctx-1", "status": {"state": "TASK_STATE_COMPLETED"}}
        }).encode(), observed_at=T2, client_agent_id="client-agent", server_agent_id="server-agent",
    )
    bundle = a2a.exchanges_to_aer([two, one], record_id="case-1/a2a")
    assert a2a.validate_aer_binding(bundle)
    kinds = {node["kind"] for node in bundle["aer"]["nodes"]}
    assert {"agent", "protocol", "context", "task", "message", "artifact"} <= kinds
    assert bundle["claims"]["task_history_complete"] is False
    assert bundle["claims"]["agent_identity_verified"] is False
    assert bundle["claims"]["delegated_authority_proven"] is False
    assert all(edge["relationship"] != "delegated_authority" for edge in bundle["aer"]["edges"])


def test_aer_binding_tamper_rejected() -> None:
    bundle = a2a.exchanges_to_aer([_exchange()], record_id="case-1/a2a")
    forged = copy.deepcopy(bundle)
    forged["exchange_record_sha256"][0] = "0" * 64
    with pytest.raises(ValueError, match="bundle hash mismatch"):
        a2a.validate_aer_binding(forged)


def test_unsupported_grpc_is_explicitly_deferred() -> None:
    with pytest.raises(ValueError, match="unsupported A2A binding"):
        a2a.capture_exchange(
            binding="GRPC", http_method="POST", path="/a2a.A2AService/SendMessage",
            request_headers={"A2A-Version": "1.0"}, request_body=b"",
            response_status=200, response_headers={}, response_body=b"",
            observed_at=T, client_agent_id="c", server_agent_id="s",
        )
