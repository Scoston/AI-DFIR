"""Evidence-preserving MCP recorder/replayer for AI-DFIR v1.8.

The replay path is deliberately inert: it parses retained protocol evidence but
never opens a network connection or invokes a tool.
"""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from typing import Any, Mapping

from v18_agent_execution_record import canonical_bytes, sha256_bytes

SCHEMA = "ai-dfir/mcp-exchange/v1.8"
MCP_SPEC_VERSION = "2026-07-28"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024


def _headers(headers: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise TypeError("headers must be a mapping")
    out: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("header keys and values must be strings")
        out[key.lower()] = value
    return dict(sorted(out.items()))


def _message(raw: bytes, name: str) -> dict[str, Any]:
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    raw = bytes(raw)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f"{name} exceeds bounded capture size")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
        raise ValueError(f"{name} must be a JSON-RPC 2.0 object")
    return {"sha256": sha256_bytes(raw), "size": len(raw), "base64": base64.b64encode(raw).decode("ascii"), "json": parsed}


def capture_exchange(request_body: bytes, response_body: bytes, *, request_headers: Mapping[str, str],
                     response_headers: Mapping[str, str], observed_at: str, transport: str = "http") -> dict[str, Any]:
    req_h, res_h = _headers(request_headers), _headers(response_headers)
    req, res = _message(request_body, "request_body"), _message(response_body, "response_body")
    method = req["json"].get("method")
    if not isinstance(method, str) or not method:
        raise ValueError("request JSON-RPC method is required")
    protocol_version = req_h.get("mcp-protocol-version") or MCP_SPEC_VERSION
    header_method = req_h.get("mcp-method")
    params = req["json"].get("params") if isinstance(req["json"].get("params"), dict) else {}
    body_name = params.get("name") if isinstance(params.get("name"), str) else None
    header_name = req_h.get("mcp-name")
    divergences: list[str] = []
    if header_method and header_method != method:
        divergences.append("mcp-method-header-does-not-match-jsonrpc-method")
    if header_name and body_name and header_name != body_name:
        divergences.append("mcp-name-header-does-not-match-request-name")
    record = {
        "schema": SCHEMA,
        "mcp_spec_version_observed": protocol_version,
        "mcp_spec_profile_target": MCP_SPEC_VERSION,
        "observed_at": observed_at,
        "transport": transport,
        "method": method,
        "name": body_name or header_name,
        "request_headers": req_h,
        "response_headers": res_h,
        "request": req,
        "response": res,
        "task_extension": method.startswith("tasks/") or bool(params.get("task")),
        "header_body_divergence": divergences,
        "claims": {"protocol_authenticity_verified": False, "server_identity_verified": False,
                   "tool_execution_replayed": False, "network_replay_performed": False},
    }
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    return record


def validate_exchange(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise ValueError("unsupported MCP evidence schema")
    for name in ("request", "response"):
        item = record.get(name)
        if not isinstance(item, dict):
            raise ValueError(f"missing {name}")
        raw = base64.b64decode(item.get("base64", ""), validate=True)
        if len(raw) != item.get("size") or sha256_bytes(raw) != item.get("sha256"):
            raise ValueError(f"{name} custody mismatch")
        if json.loads(raw.decode("utf-8")) != item.get("json"):
            raise ValueError(f"{name} parsed JSON mismatch")
    claims = record.get("claims")
    if not isinstance(claims, dict) or claims.get("tool_execution_replayed") is not False or claims.get("network_replay_performed") is not False:
        raise ValueError("MCP replay safety claims invalid")
    digest = record.get("record_sha256")
    unsigned = deepcopy(record); unsigned.pop("record_sha256", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("MCP record hash mismatch")
    return True


def replay_offline(record: dict[str, Any]) -> dict[str, Any]:
    """Return retained request/response for analysis without executing anything."""
    validate_exchange(record)
    return {
        "method": record["method"],
        "name": record.get("name"),
        "request": deepcopy(record["request"]["json"]),
        "response": deepcopy(record["response"]["json"]),
        "header_body_divergence": list(record["header_body_divergence"]),
        "network_performed": False,
        "tool_executed": False,
    }
