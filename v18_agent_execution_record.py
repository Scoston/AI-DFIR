"""AI-DFIR v1.8 Agent Execution Record (AER).

AER captures observable autonomous execution and evidence bindings. It does not
store or claim access to private model chain-of-thought.
"""
from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Iterable

SCHEMA = "ai-dfir/agent-execution-record/v1.8"
VERSION = "1.8"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NODE_KINDS = {
    "trigger", "human", "agent", "context", "retrieval", "memory", "policy",
    "identity", "model", "tool", "protocol", "action", "resource", "side_effect",
    "approval", "workflow", "task", "message", "artifact", "unknown",
}
RELATIONSHIPS = {
    "triggered", "instructed", "provided_context", "retrieved", "read_memory",
    "wrote_memory", "evaluated_policy", "approved", "denied", "delegated_authority",
    "selected_tool", "invoked", "communicated_with", "acted_on", "changed",
    "produced", "observed", "derived_from", "correlated_with",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    return hashlib.sha256(bytes(data)).hexdigest()


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _time(value: str) -> str:
    _text(value, "timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    return value


def evidence_ref(artifact_type: str, sha256: str, size: int, *, locator: str | None = None,
                 chunk_id: str | None = None, observed_at: str | None = None) -> dict[str, Any]:
    _text(artifact_type, "artifact_type")
    if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
        raise ValueError("sha256 must be lowercase hexadecimal SHA-256")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("size must be a non-negative integer")
    out: dict[str, Any] = {"artifact_type": artifact_type, "sha256": sha256, "size": size}
    if locator is not None:
        out["locator"] = _text(locator, "locator")
    if chunk_id is not None:
        out["chunk_id"] = _text(chunk_id, "chunk_id")
    if observed_at is not None:
        out["observed_at"] = _time(observed_at)
    return out


def node(node_id: str, kind: str, observed_at: str, *, attributes: dict[str, Any] | None = None,
         evidence_refs: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    _text(node_id, "node_id")
    if kind not in NODE_KINDS:
        raise ValueError(f"unsupported node kind: {kind}")
    _time(observed_at)
    if attributes is not None and not isinstance(attributes, dict):
        raise TypeError("attributes must be a dict")
    return {"node_id": node_id, "kind": kind, "observed_at": observed_at,
            "attributes": deepcopy(attributes or {}),
            "evidence_refs": [deepcopy(x) for x in evidence_refs]}


def edge(edge_id: str, source_node: str, target_node: str, relationship: str, *,
         evidence_refs: Iterable[dict[str, Any]] = (), authority_context: dict[str, Any] | None = None,
         policy_context: dict[str, Any] | None = None, approval_context: dict[str, Any] | None = None,
         confidence: str = "unknown", unknown_fields: Iterable[str] = ()) -> dict[str, Any]:
    for value, name in ((edge_id, "edge_id"), (source_node, "source_node"), (target_node, "target_node")):
        _text(value, name)
    if relationship not in RELATIONSHIPS:
        raise ValueError(f"unsupported relationship: {relationship}")
    if confidence not in {"observed", "corroborated", "inferred", "unknown"}:
        raise ValueError("unsupported confidence")
    unknown = list(unknown_fields)
    if any(not isinstance(x, str) or not x for x in unknown):
        raise ValueError("unknown_fields entries must be non-empty strings")
    return {"edge_id": edge_id, "source_node": source_node, "target_node": target_node,
            "relationship": relationship, "evidence_refs": [deepcopy(x) for x in evidence_refs],
            "authority_context": deepcopy(authority_context or {}),
            "policy_context": deepcopy(policy_context or {}),
            "approval_context": deepcopy(approval_context or {}),
            "confidence": confidence, "unknown_fields": unknown}


def _check_ref(ref: dict[str, Any]) -> None:
    if not isinstance(ref, dict):
        raise ValueError("evidence reference must be an object")
    evidence_ref(ref.get("artifact_type"), ref.get("sha256"), ref.get("size"),
                 locator=ref.get("locator"), chunk_id=ref.get("chunk_id"), observed_at=ref.get("observed_at"))


def build_record(record_id: str, started_at: str, *, ended_at: str | None = None,
                 nodes: Iterable[dict[str, Any]] = (), edges: Iterable[dict[str, Any]] = (),
                 source_versions: dict[str, str] | None = None,
                 raw_evidence: Iterable[dict[str, Any]] = (), claims: dict[str, bool] | None = None) -> dict[str, Any]:
    record = {"schema": SCHEMA, "version": VERSION, "record_id": _text(record_id, "record_id"),
              "started_at": _time(started_at), "ended_at": _time(ended_at) if ended_at else None,
              "source_versions": deepcopy(source_versions or {}), "nodes": [deepcopy(x) for x in nodes],
              "edges": [deepcopy(x) for x in edges], "raw_evidence": [deepcopy(x) for x in raw_evidence],
              "claims": {"source_authenticity_verified": False, "complete_context_captured": False,
                         "private_reasoning_captured": False, "causal_intent_proven": False, **deepcopy(claims or {})}}
    validate_record(record, require_hash=False)
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    validate_record(record)
    return record


def validate_record(record: dict[str, Any], *, require_hash: bool = True) -> bool:
    if not isinstance(record, dict) or record.get("schema") != SCHEMA or record.get("version") != VERSION:
        raise ValueError("unsupported AER schema/version")
    _text(record.get("record_id"), "record_id")
    _time(record.get("started_at"))
    if record.get("ended_at") is not None:
        _time(record["ended_at"])
    versions = record.get("source_versions")
    if not isinstance(versions, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in versions.items()):
        raise ValueError("source_versions must map strings to strings")
    nodes, edges, raw = record.get("nodes"), record.get("edges"), record.get("raw_evidence")
    if not isinstance(nodes, list) or not isinstance(edges, list) or not isinstance(raw, list):
        raise ValueError("nodes, edges and raw_evidence must be arrays")
    node_ids: set[str] = set()
    for n in nodes:
        if not isinstance(n, dict):
            raise ValueError("node must be an object")
        nid = _text(n.get("node_id"), "node_id")
        if nid in node_ids:
            raise ValueError("duplicate node_id")
        node_ids.add(nid)
        if n.get("kind") not in NODE_KINDS:
            raise ValueError("unsupported node kind")
        _time(n.get("observed_at"))
        if not isinstance(n.get("attributes"), dict) or not isinstance(n.get("evidence_refs"), list):
            raise ValueError("invalid node payload")
        for ref in n["evidence_refs"]:
            _check_ref(ref)
    edge_ids: set[str] = set()
    for e in edges:
        if not isinstance(e, dict):
            raise ValueError("edge must be an object")
        eid = _text(e.get("edge_id"), "edge_id")
        if eid in edge_ids:
            raise ValueError("duplicate edge_id")
        edge_ids.add(eid)
        if e.get("source_node") not in node_ids or e.get("target_node") not in node_ids:
            raise ValueError("edge references missing node")
        if e.get("relationship") not in RELATIONSHIPS:
            raise ValueError("unsupported relationship")
        if e.get("confidence") not in {"observed", "corroborated", "inferred", "unknown"}:
            raise ValueError("unsupported confidence")
        for key in ("authority_context", "policy_context", "approval_context"):
            if not isinstance(e.get(key), dict):
                raise ValueError(f"{key} must be an object")
        if not isinstance(e.get("unknown_fields"), list):
            raise ValueError("unknown_fields must be an array")
        for ref in e.get("evidence_refs", []):
            _check_ref(ref)
    for ref in raw:
        _check_ref(ref)
    claims = record.get("claims")
    if not isinstance(claims, dict) or any(type(v) is not bool for v in claims.values()):
        raise ValueError("claims must map strings to booleans")
    if claims.get("private_reasoning_captured") is not False:
        raise ValueError("private_reasoning_captured must remain false")
    if require_hash:
        digest = record.get("record_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError("missing/invalid record_sha256")
        unsigned = deepcopy(record); unsigned.pop("record_sha256", None)
        if sha256_bytes(canonical_bytes(unsigned)) != digest:
            raise ValueError("record hash mismatch")
    return True
