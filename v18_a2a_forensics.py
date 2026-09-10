"""Versioned Agent2Agent (A2A) protocol evidence capture for AI-DFIR v1.8.

The profile targets released A2A 1.0 semantics for JSON-RPC and HTTP+JSON
bindings. It preserves protocol bodies and fingerprints reusable credential
headers without retaining their raw values. It does not verify Agent Card JWS
signatures; existing AI-DFIR A2A trust evidence remains a separate proposition.
"""
from __future__ import annotations

import base64
import json
import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlsplit

import v18_agent_execution_record as aer

EXCHANGE_SCHEMA = "ai-dfir/a2a-exchange/v1.8"
STREAM_SCHEMA = "ai-dfir/a2a-sse-stream/v1.8"
AER_BINDING_SCHEMA = "ai-dfir/a2a-aer-binding/v1.8"
AGENT_CARD_SCHEMA = "ai-dfir/a2a-agent-card-observation/v1.8"
A2A_RELEASE = "1.0.0"
A2A_MAJOR_MINOR = "1.0"
SUPPORTED_BINDINGS = {"JSONRPC", "HTTP+JSON"}
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 32 * 1024 * 1024
MAX_STREAM_EVENTS = 10_000
MAX_HEADERS = 256
MAX_EXCHANGES_PER_AER = 10_000
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "api-key", "x-goog-api-key", "x-auth-token",
}
CORE_JSONRPC_METHODS = {
    "SendMessage", "SendStreamingMessage", "GetTask", "ListTasks", "CancelTask",
    "SubscribeToTask", "CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
}


def _time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("observed_at must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid observed_at") from exc
    return value


def _body(value: bytes | bytearray | None, name: str) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    raw = bytes(value)
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError(f"{name} exceeds byte bound")
    return raw


def _strict_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("A2A JSON body must be UTF-8") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value is not permitted: {value}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid A2A JSON") from exc


def _header_pairs(headers: dict[str, Any] | Iterable[tuple[str, Any]] | None) -> list[tuple[str, str]]:
    if headers is None:
        return []
    items = headers.items() if isinstance(headers, dict) else headers
    pairs: list[tuple[str, str]] = []
    for name, value in items:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("header name must be a non-empty string")
        if not isinstance(value, str):
            raise ValueError("header values must be strings")
        pairs.append((name.strip().lower(), value))
    if len(pairs) > MAX_HEADERS:
        raise ValueError("header count exceeds bound")
    return pairs


def _headers(headers: dict[str, Any] | Iterable[tuple[str, Any]] | None) -> dict[str, Any]:
    pairs = _header_pairs(headers)
    values: dict[str, list[str]] = {}
    for name, value in pairs:
        values.setdefault(name, []).append(value)
    safe: dict[str, list[str]] = {}
    sensitive: dict[str, list[dict[str, Any]]] = {}
    for name in sorted(values):
        if name in SENSITIVE_HEADERS:
            observations = []
            for value in values[name]:
                scheme = value.split(None, 1)[0] if value.strip() else None
                observations.append({
                    "scheme": scheme,
                    "sha256": aer.sha256_bytes(value.encode("utf-8")),
                    "length": len(value.encode("utf-8")),
                })
            sensitive[name] = observations
        else:
            safe[name] = list(values[name])
    return {
        "names": sorted(values),
        "safe_values": safe,
        "sensitive_fingerprints": sensitive,
        "credential_values_retained": False,
    }


def _one_header(captured: dict[str, Any], name: str) -> str | None:
    vals = captured.get("safe_values", {}).get(name.lower(), [])
    if not vals:
        return None
    if len(vals) != 1:
        raise ValueError(f"multiple {name} headers are ambiguous")
    return vals[0]


def _version_observation(request_headers: dict[str, Any]) -> dict[str, Any]:
    observed = _one_header(request_headers, "a2a-version")
    if observed is None or observed == "":
        return {
            "observed": observed,
            "effective_major_minor": "0.3",
            "source": "spec-default-empty",
            "matches_profile": False,
            "missing_for_1_0_client": True,
        }
    if not VERSION_RE.fullmatch(observed):
        raise ValueError("A2A-Version must be Major.Minor")
    return {
        "observed": observed,
        "effective_major_minor": observed,
        "source": "header",
        "matches_profile": observed == A2A_MAJOR_MINOR,
        "missing_for_1_0_client": False,
    }


def _extensions(request_headers: dict[str, Any]) -> list[str]:
    raw = _one_header(request_headers, "a2a-extensions")
    if not raw:
        return []
    return sorted({item.strip() for item in raw.split(",") if item.strip()})


def _http_operation(method: str, path: str) -> str | None:
    method = method.upper()
    route = urlsplit(path).path
    patterns = [
        ("POST", r"/message:send", "SendMessage"),
        ("POST", r"/message:stream", "SendStreamingMessage"),
        ("GET", r"/tasks", "ListTasks"),
        ("GET", r"/tasks/[^/]+", "GetTask"),
        ("POST", r"/tasks/[^/]+:cancel", "CancelTask"),
        ("POST", r"/tasks/[^/]+:subscribe", "SubscribeToTask"),
        ("POST", r"/tasks/[^/]+/pushNotificationConfigs", "CreateTaskPushNotificationConfig"),
        ("GET", r"/tasks/[^/]+/pushNotificationConfigs", "ListTaskPushNotificationConfigs"),
        ("GET", r"/tasks/[^/]+/pushNotificationConfigs/[^/]+", "GetTaskPushNotificationConfig"),
        ("DELETE", r"/tasks/[^/]+/pushNotificationConfigs/[^/]+", "DeleteTaskPushNotificationConfig"),
        ("GET", r"/extendedAgentCard", "GetExtendedAgentCard"),
    ]
    for expected_method, pattern, operation in patterns:
        if method == expected_method and re.fullmatch(pattern, route):
            return operation
    return None


def _jsonrpc_observation(body: Any) -> dict[str, Any]:
    if body is None:
        return {"present": False, "method": None, "id": None, "error_code": None}
    if not isinstance(body, dict):
        raise ValueError("JSON-RPC body must be an object")
    if body.get("jsonrpc") != "2.0":
        raise ValueError("JSON-RPC version must be 2.0")
    method = body.get("method")
    if method is not None and not isinstance(method, str):
        raise ValueError("JSON-RPC method must be a string")
    error = body.get("error")
    error_code = error.get("code") if isinstance(error, dict) else None
    return {
        "present": True,
        "method": method,
        "id": deepcopy(body.get("id")),
        "method_is_known_1_0": method in CORE_JSONRPC_METHODS if method is not None else None,
        "error_code": error_code,
    }


def _body_custody(raw: bytes) -> dict[str, Any]:
    return {
        "sha256": aer.sha256_bytes(raw),
        "size": len(raw),
        "base64": base64.b64encode(raw).decode("ascii"),
    }


def _validate_body_custody(custody: dict[str, Any]) -> bytes:
    if not isinstance(custody, dict):
        raise ValueError("body custody missing")
    try:
        raw = base64.b64decode(custody.get("base64", ""), validate=True)
    except Exception as exc:
        raise ValueError("invalid body base64") from exc
    if custody.get("size") != len(raw) or custody.get("sha256") != aer.sha256_bytes(raw):
        raise ValueError("body custody mismatch")
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError("retained body exceeds byte bound")
    return raw


def capture_exchange(*, binding: str, http_method: str, path: str,
                     request_headers: dict[str, Any] | Iterable[tuple[str, Any]] | None,
                     request_body: bytes | bytearray | None,
                     response_status: int,
                     response_headers: dict[str, Any] | Iterable[tuple[str, Any]] | None,
                     response_body: bytes | bytearray | None,
                     observed_at: str,
                     client_agent_id: str,
                     server_agent_id: str,
                     agent_card_sha256: str | None = None) -> dict[str, Any]:
    if binding not in SUPPORTED_BINDINGS:
        raise ValueError("unsupported A2A binding")
    if not isinstance(http_method, str) or not http_method:
        raise ValueError("http_method is required")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("path must start with /")
    if isinstance(response_status, bool) or not isinstance(response_status, int) or not 100 <= response_status <= 599:
        raise ValueError("invalid response_status")
    for value, name in ((client_agent_id, "client_agent_id"), (server_agent_id, "server_agent_id")):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} is required")
    if agent_card_sha256 is not None and not aer.SHA256_RE.fullmatch(agent_card_sha256):
        raise ValueError("agent_card_sha256 must be lowercase SHA-256")
    observed_at = _time(observed_at)
    request_raw = _body(request_body, "request_body")
    response_raw = _body(response_body, "response_body")
    req_headers = _headers(request_headers)
    res_headers = _headers(response_headers)
    request_json = _strict_json(request_raw) if request_raw else None
    response_json = _strict_json(response_raw) if response_raw else None
    version = _version_observation(req_headers)

    if binding == "JSONRPC":
        operation = _jsonrpc_observation(request_json).get("method")
        request_protocol = _jsonrpc_observation(request_json)
        response_protocol = _jsonrpc_observation(response_json) if response_json is not None else {"present": False, "method": None, "id": None, "error_code": None}
    else:
        operation = _http_operation(http_method, path)
        request_protocol = {"present": request_json is not None, "method": None, "id": None, "error_code": None}
        response_protocol = {"present": response_json is not None, "method": None, "id": None,
                             "error_code": response_json.get("error", {}).get("code") if isinstance(response_json, dict) and isinstance(response_json.get("error"), dict) else None}

    record = {
        "schema": EXCHANGE_SCHEMA,
        "a2a_release_profile": A2A_RELEASE,
        "binding": binding,
        "observed_at": observed_at,
        "client_agent_id": client_agent_id,
        "server_agent_id": server_agent_id,
        "http": {
            "method": http_method.upper(),
            "path": path,
            "response_status": response_status,
        },
        "request_headers": req_headers,
        "response_headers": res_headers,
        "service_parameters": {
            "version": version,
            "extensions": _extensions(req_headers),
        },
        "operation": operation,
        "request_protocol": request_protocol,
        "response_protocol": response_protocol,
        "request_body": _body_custody(request_raw),
        "response_body": _body_custody(response_raw),
        "agent_card_sha256": agent_card_sha256,
        "claims": {
            "protocol_body_bytes_preserved": True,
            "credential_header_values_retained": False,
            "transport_authentication_verified": False,
            "agent_card_trust_verified_by_this_module": False,
            "request_authorized": False,
            "task_semantics_complete": False,
            "causal_intent_proven": False,
            "private_reasoning_captured": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    validate_exchange(record)
    return record


def validate_exchange(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != EXCHANGE_SCHEMA:
        raise ValueError("unsupported A2A exchange schema")
    if record.get("binding") not in SUPPORTED_BINDINGS:
        raise ValueError("unsupported A2A binding")
    _time(record.get("observed_at"))
    _validate_body_custody(record.get("request_body"))
    _validate_body_custody(record.get("response_body"))
    for key in ("request_headers", "response_headers"):
        headers = record.get(key)
        if not isinstance(headers, dict) or headers.get("credential_values_retained") is not False:
            raise ValueError("invalid captured headers")
        if not isinstance(headers.get("names"), list) or not isinstance(headers.get("safe_values"), dict) or not isinstance(headers.get("sensitive_fingerprints"), dict):
            raise ValueError("invalid captured header structure")
        if any(name in SENSITIVE_HEADERS for name in headers["safe_values"]):
            raise ValueError("sensitive header value retained")
    version = record.get("service_parameters", {}).get("version")
    if not isinstance(version, dict):
        raise ValueError("A2A version observation missing")
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("claims missing")
    for key in ("credential_header_values_retained", "transport_authentication_verified",
                "agent_card_trust_verified_by_this_module", "request_authorized",
                "task_semantics_complete", "causal_intent_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(record)
    digest = unsigned.pop("record_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("A2A exchange record hash mismatch")
    return True


def observe_agent_card(card_bytes: bytes | bytearray, *, observed_at: str,
                       source_locator: str | None = None) -> dict[str, Any]:
    raw = _body(card_bytes, "agent_card")
    card = _strict_json(raw)
    if not isinstance(card, dict):
        raise ValueError("Agent Card must be a JSON object")
    if not isinstance(card.get("name"), str) or not isinstance(card.get("version"), str):
        raise ValueError("Agent Card name/version missing")
    interfaces = card.get("supportedInterfaces")
    if not isinstance(interfaces, list) or not interfaces:
        raise ValueError("Agent Card supportedInterfaces missing")
    summarized_interfaces = []
    for item in interfaces:
        if not isinstance(item, dict):
            raise ValueError("invalid AgentInterface")
        summarized_interfaces.append({
            "url": item.get("url"),
            "protocolBinding": item.get("protocolBinding"),
            "protocolVersion": item.get("protocolVersion"),
            "tenant": item.get("tenant"),
        })
    skills = card.get("skills") or []
    if not isinstance(skills, list):
        raise ValueError("Agent Card skills must be an array")
    record = {
        "schema": AGENT_CARD_SCHEMA,
        "observed_at": _time(observed_at),
        "source_locator": source_locator,
        "body": _body_custody(raw),
        "summary": {
            "name": card.get("name"),
            "agent_version": card.get("version"),
            "provider": deepcopy(card.get("provider")),
            "supported_interfaces": summarized_interfaces,
            "skill_ids": sorted(str(item.get("id")) for item in skills if isinstance(item, dict) and item.get("id") is not None),
            "signature_count": len(card.get("signatures") or []) if isinstance(card.get("signatures") or [], list) else None,
        },
        "claims": {
            "card_bytes_preserved": True,
            "card_signature_verified_by_this_module": False,
            "provider_trusted": False,
            "interface_trusted": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    return record


def _stream_payload(binding: str, payload: Any) -> dict[str, Any]:
    if binding == "JSONRPC":
        observation = _jsonrpc_observation(payload)
        if not isinstance(payload, dict) or "result" not in payload:
            raise ValueError("JSON-RPC SSE event must contain result")
        result = payload["result"]
        if not isinstance(result, dict):
            raise ValueError("JSON-RPC stream result must be an object")
        return {"wrapper": observation, "stream_response": deepcopy(result)}
    if not isinstance(payload, dict):
        raise ValueError("HTTP+JSON SSE event must be an object")
    return {"wrapper": None, "stream_response": deepcopy(payload)}


def capture_sse_stream(raw_stream: bytes | bytearray, *, binding: str, observed_at: str) -> dict[str, Any]:
    if binding not in SUPPORTED_BINDINGS:
        raise ValueError("unsupported A2A binding")
    if not isinstance(raw_stream, (bytes, bytearray)):
        raise TypeError("raw_stream must be bytes")
    raw = bytes(raw_stream)
    if len(raw) > MAX_STREAM_BYTES:
        raise ValueError("A2A SSE stream exceeds byte bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("A2A SSE must be UTF-8") from exc
    events: list[dict[str, Any]] = []
    current_data: list[str] = []
    for line in text.splitlines() + [""]:
        if line == "":
            if current_data:
                payload_raw = "\n".join(current_data).encode("utf-8")
                payload = _strict_json(payload_raw)
                parsed = _stream_payload(binding, payload)
                stream = parsed["stream_response"]
                keys = [key for key in ("task", "message", "statusUpdate", "artifactUpdate") if key in stream]
                if len(keys) != 1:
                    raise ValueError("A2A StreamResponse must contain exactly one event object")
                events.append({
                    "sequence": len(events),
                    "event_type": keys[0],
                    "payload_sha256": aer.sha256_bytes(payload_raw),
                    "payload": parsed,
                })
                if len(events) > MAX_STREAM_EVENTS:
                    raise ValueError("A2A SSE event count exceeds bound")
                current_data = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            value = line[5:]
            if value.startswith(" "):
                value = value[1:]
            current_data.append(value)
    record = {
        "schema": STREAM_SCHEMA,
        "binding": binding,
        "observed_at": _time(observed_at),
        "raw_stream": {
            "sha256": aer.sha256_bytes(raw),
            "size": len(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        },
        "events": events,
        "claims": {
            "stream_bytes_preserved": True,
            "delivery_complete": False,
            "reconnection_gap_free": False,
            "event_business_causality_proven": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    return record


def _walk_objects(value: Any, *, path: str = "$") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if isinstance(value.get("messageId"), str) and isinstance(value.get("parts"), list) and value.get("role") is not None:
            out.append({"kind": "message", "object_id": value["messageId"], "task_id": value.get("taskId"),
                        "context_id": value.get("contextId"), "path": path, "value": deepcopy(value)})
        if isinstance(value.get("artifactId"), str) and isinstance(value.get("parts"), list):
            out.append({"kind": "artifact", "object_id": value["artifactId"], "task_id": None,
                        "context_id": None, "path": path, "value": deepcopy(value)})
        if isinstance(value.get("id"), str) and isinstance(value.get("status"), dict) and value["status"].get("state") is not None:
            out.append({"kind": "task", "object_id": value["id"], "task_id": value["id"],
                        "context_id": value.get("contextId"), "path": path, "value": deepcopy(value)})
        if isinstance(value.get("taskId"), str) and isinstance(value.get("status"), dict) and value.get("contextId") is not None:
            out.append({"kind": "task", "object_id": value["taskId"], "task_id": value["taskId"],
                        "context_id": value.get("contextId"), "path": path + ":status-update", "value": deepcopy(value)})
        if isinstance(value.get("taskId"), str) and isinstance(value.get("artifact"), dict) and value.get("contextId") is not None:
            artifact = value["artifact"]
            if isinstance(artifact.get("artifactId"), str):
                out.append({"kind": "artifact", "object_id": artifact["artifactId"], "task_id": value["taskId"],
                            "context_id": value.get("contextId"), "path": path + ":artifact-update", "value": deepcopy(artifact)})
        for key, child in value.items():
            out.extend(_walk_objects(child, path=f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(_walk_objects(child, path=f"{path}[{index}]"))
    return out


def _decoded_body(custody: dict[str, Any]) -> Any:
    raw = _validate_body_custody(custody)
    return _strict_json(raw) if raw else None


def exchanges_to_aer(exchanges: Iterable[dict[str, Any]], *, record_id: str) -> dict[str, Any]:
    records = [deepcopy(item) for item in exchanges]
    if not records:
        raise ValueError("at least one A2A exchange is required")
    if len(records) > MAX_EXCHANGES_PER_AER:
        raise ValueError("A2A exchange count exceeds AER bound")
    for item in records:
        validate_exchange(item)
    records.sort(key=lambda item: (item["observed_at"], item["record_sha256"]))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    raw_refs: list[dict[str, Any]] = []
    agent_nodes: dict[str, str] = {}
    context_nodes: dict[str, str] = {}

    def ensure_agent(agent_id: str, observed_at: str) -> str:
        node_id = f"a2a-agent:{agent_id}"
        if node_id not in agent_nodes.values():
            nodes.append(aer.node(node_id, "agent", observed_at, attributes={"a2a_agent_id": agent_id}))
        agent_nodes[agent_id] = node_id
        return node_id

    def ensure_context(context_id: str, observed_at: str) -> str:
        node_id = f"a2a-context:{context_id}"
        if node_id not in context_nodes.values():
            nodes.append(aer.node(node_id, "context", observed_at, attributes={"a2a_context_id": context_id}))
        context_nodes[context_id] = node_id
        return node_id

    for index, item in enumerate(records):
        request_raw = _validate_body_custody(item["request_body"])
        response_raw = _validate_body_custody(item["response_body"])
        req_ref = aer.evidence_ref("a2a-request-body", item["request_body"]["sha256"], len(request_raw),
                                   locator=f"a2a:{item['record_sha256']}:request", observed_at=item["observed_at"])
        res_ref = aer.evidence_ref("a2a-response-body", item["response_body"]["sha256"], len(response_raw),
                                   locator=f"a2a:{item['record_sha256']}:response", observed_at=item["observed_at"])
        raw_refs.extend([req_ref, res_ref])
        client = ensure_agent(item["client_agent_id"], item["observed_at"])
        server = ensure_agent(item["server_agent_id"], item["observed_at"])
        protocol_id = f"a2a-exchange:{index:06d}:{item['record_sha256'][:16]}"
        nodes.append(aer.node(protocol_id, "protocol", item["observed_at"], attributes={
            "binding": item["binding"],
            "a2a_release_profile": item["a2a_release_profile"],
            "effective_protocol_version": item["service_parameters"]["version"]["effective_major_minor"],
            "operation": item.get("operation"),
            "http": deepcopy(item["http"]),
            "extensions": deepcopy(item["service_parameters"]["extensions"]),
            "agent_card_sha256": item.get("agent_card_sha256"),
        }, evidence_refs=[req_ref, res_ref]))
        edges.append(aer.edge(f"edge:{protocol_id}:client", client, protocol_id, "communicated_with",
                              evidence_refs=[req_ref], confidence="observed",
                              unknown_fields=["request_authorization", "human_intent"]))
        edges.append(aer.edge(f"edge:{protocol_id}:server", protocol_id, server, "communicated_with",
                              evidence_refs=[res_ref], confidence="observed",
                              unknown_fields=["server_identity_authenticity", "business_causality"]))

        observations: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for direction, custody, ref in (("request", item["request_body"], req_ref), ("response", item["response_body"], res_ref)):
            decoded = _decoded_body(custody)
            for obj in _walk_objects(decoded):
                observations.append((direction, obj, ref))

        seen_local: set[tuple[str, str, str, str]] = set()
        for ordinal, (direction, obj, ref) in enumerate(observations):
            obj_bytes = aer.canonical_bytes(obj["value"])
            obj_hash = aer.sha256_bytes(obj_bytes)
            key = (obj["kind"], obj["object_id"], direction, obj_hash)
            if key in seen_local:
                continue
            seen_local.add(key)
            object_node = f"{protocol_id}:{obj['kind']}:{ordinal:04d}:{obj['object_id']}"
            attrs = {
                "a2a_object_id": obj["object_id"],
                "direction": direction,
                "json_path": obj["path"],
                "object_sha256": obj_hash,
                "task_id": obj.get("task_id"),
                "context_id": obj.get("context_id"),
            }
            if obj["kind"] == "task":
                status = obj["value"].get("status")
                attrs["state"] = status.get("state") if isinstance(status, dict) else None
            elif obj["kind"] == "message":
                attrs["role"] = obj["value"].get("role")
                attrs["reference_task_ids"] = deepcopy(obj["value"].get("referenceTaskIds") or [])
            elif obj["kind"] == "artifact":
                attrs["name"] = obj["value"].get("name")
            nodes.append(aer.node(object_node, obj["kind"], item["observed_at"], attributes=attrs, evidence_refs=[ref]))
            relationship = "provided_context" if direction == "request" and obj["kind"] == "message" else "produced" if direction == "response" and obj["kind"] in {"message", "artifact"} else "observed"
            edges.append(aer.edge(f"edge:{object_node}:protocol", protocol_id, object_node, relationship,
                                  evidence_refs=[ref], confidence="observed",
                                  unknown_fields=["semantic_completeness", "causal_effect"]))
            if obj.get("context_id"):
                context = ensure_context(str(obj["context_id"]), item["observed_at"])
                edges.append(aer.edge(f"edge:{object_node}:context", object_node, context, "correlated_with",
                                      evidence_refs=[ref], confidence="observed",
                                      unknown_fields=["context_history_completeness"]))

    # Correlate repeated task IDs across observations without asserting causality.
    task_nodes: dict[str, list[str]] = {}
    for n in nodes:
        if n["kind"] == "task" and n["attributes"].get("task_id"):
            task_nodes.setdefault(str(n["attributes"]["task_id"]), []).append(n["node_id"])
    for task_id, ids in sorted(task_nodes.items()):
        ids = sorted(ids)
        for left, right in zip(ids, ids[1:]):
            edge_id = f"edge:a2a-task-correlation:{aer.sha256_bytes((left + '|' + right).encode())[:20]}"
            edges.append(aer.edge(edge_id, left, right, "correlated_with", confidence="observed",
                                  unknown_fields=["task_history_completeness", "causal_transition"]))

    nodes.sort(key=lambda n: n["node_id"])
    edges.sort(key=lambda e: e["edge_id"])
    raw_refs.sort(key=lambda r: (r["sha256"], r.get("locator", "")))
    started_at = min(records, key=lambda x: x["observed_at"])["observed_at"]
    ended_at = max(records, key=lambda x: x["observed_at"])["observed_at"]
    record = aer.build_record(
        record_id, started_at, ended_at=ended_at, nodes=nodes, edges=edges,
        raw_evidence=raw_refs,
        source_versions={"a2a": A2A_RELEASE, "a2a_capture": EXCHANGE_SCHEMA},
        claims={"complete_context_captured": False, "causal_intent_proven": False},
    )
    bundle = {
        "schema": AER_BINDING_SCHEMA,
        "aer": record,
        "exchange_record_sha256": [item["record_sha256"] for item in records],
        "claims": {
            "a2a_exchange_bodies_bound": True,
            "task_history_complete": False,
            "agent_identity_verified": False,
            "delegated_authority_proven": False,
            "causal_intent_proven": False,
            "private_reasoning_captured": False,
        },
    }
    bundle["bundle_sha256"] = aer.sha256_bytes(aer.canonical_bytes(bundle))
    validate_aer_binding(bundle)
    return bundle


def validate_aer_binding(bundle: dict[str, Any]) -> bool:
    if not isinstance(bundle, dict) or bundle.get("schema") != AER_BINDING_SCHEMA:
        raise ValueError("unsupported A2A AER binding schema")
    aer.validate_record(bundle.get("aer"))
    if not isinstance(bundle.get("exchange_record_sha256"), list) or not bundle["exchange_record_sha256"]:
        raise ValueError("exchange bindings missing")
    if any(not isinstance(x, str) or not aer.SHA256_RE.fullmatch(x) for x in bundle["exchange_record_sha256"]):
        raise ValueError("invalid exchange hash binding")
    claims = bundle.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("claims missing")
    for key in ("task_history_complete", "agent_identity_verified", "delegated_authority_proven",
                "causal_intent_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(bundle)
    digest = unsigned.pop("bundle_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("A2A AER bundle hash mismatch")
    return True
