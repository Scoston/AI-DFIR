"""Validated evidence lineage and recorded investigation provenance.

This optional v1.7 profile binds typed records to ledger events. It records
observable activity only; it never invokes a model, tool, or evidence-supplied
command. Legacy v1.7 record/signature hash formats remain unchanged.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Mapping

from v17_integrity import (
    AIProvenanceRecord, AnalystDecisionRecord, EvidenceArtifact,
    EvidenceRelationship, InvestigationLedger, canonical_json_bytes, sha256_object,
)

PROVENANCE_SCHEMA = "ai-dfir/investigation-provenance/v1.7"
PROVENANCE_PATH = "00_case/v17/investigation_provenance.json"
MAX_RECORDS = 10_000
MAX_PROVENANCE_BYTES = 16 * 1024**2
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")
_SENSITIVE_FIELDS = {
    "prompt", "raw_prompt", "messages", "authorization", "password", "secret",
    "api_key", "access_token", "refresh_token", "chain_of_thought", "hidden_reasoning",
}


@dataclass(frozen=True)
class ToolActivityRecord:
    case_id: str
    activity_id: str
    invocation_id: str
    tool_name: str
    actor: str
    timestamp: str
    status: str
    arguments_sha256: str
    evidence_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()


_TYPES = {
    "artifacts": (EvidenceArtifact, "artifact_id", "EVIDENCE_ACQUIRED"),
    "relationships": (EvidenceRelationship, None, "EVIDENCE_LINKED"),
    "ai_records": (AIProvenanceRecord, "invocation_id", "MODEL_INVOKED"),
    "tool_records": (ToolActivityRecord, "activity_id", "TOOL_INVOKED"),
    "analyst_decisions": (AnalystDecisionRecord, "decision_id", "ANALYST_REVIEWED"),
}


class ProvenanceError(ValueError):
    """An incomplete, inconsistent, or unsupported provenance profile."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProvenanceError(message)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def utc_timestamp(value: Any) -> datetime:
    """Require an explicit UTC instant; never guess a timezone from a log."""
    _require(isinstance(value, str) and _UTC.fullmatch(value) is not None, "invalid RFC 3339 UTC timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProvenanceError("invalid calendar timestamp") from exc


def _path(value: Any) -> bool:
    return (
        _text(value) and "\\" not in value and ":" not in value
        and not any(ord(c) < 32 for c in value)
        and not PurePosixPath(value).is_absolute()
        and all(p not in {"", ".", ".."} for p in value.split("/"))
    )


def _check_content(value: Any) -> None:
    """Reject known sensitive field names; this is not a PII/secret classifier."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            _require(not (_SENSITIVE_FIELDS & {str(k).lower() for k in item}), "prohibited sensitive-context field")
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)


def record_hash(row: Mapping[str, Any]) -> str:
    """Bind the record type, content, evidence path, and recorded output digest."""
    return sha256_object({k: v for k, v in row.items() if k != "record_hash"})


def wrap_record(kind: str, record: Any, *, path: str | None = None) -> dict[str, Any]:
    _require(kind in _TYPES, "unsupported provenance record type")
    _require(type(record) is _TYPES[kind][0], "record type mismatch")
    row = {"schema": f"ai-dfir/provenance/{kind}/v1.7", "record": asdict(record)}
    if kind == "artifacts":
        _require(_path(path), "artifact requires a safe package-relative path")
        row["path"] = path
    else:
        _require(path is None, "only artifact records have paths")
    if kind == "ai_records":
        row["output_sha256"] = sha256_object(record.structured_output) if record.structured_output else None
    row["record_hash"] = record_hash(row)
    return row


def new_provenance(case_id: str) -> dict[str, Any]:
    return {
        "schema": PROVENANCE_SCHEMA, "case_id": case_id,
        "content_policy": "references-only", "content_review": None,
        **{kind: [] for kind in _TYPES}, "comparisons": [],
    }


def bind_record(ledger: InvestigationLedger, kind: str, row: Mapping[str, Any], *, timestamp: str, actor: str):
    """Append a record commitment before creating and signing the checkpoint."""
    _require(kind in _TYPES, "unsupported provenance record type")
    utc_timestamp(timestamp)
    id_field = _TYPES[kind][1]
    return ledger.append(
        event_type=_TYPES[kind][2], timestamp=timestamp, actor=actor,
        payload={
            "provenance_type": kind,
            "record_id": row["record"][id_field] if id_field else row["record_hash"],
            "record_hash": row["record_hash"],
        },
    )


def validate_provenance(
    bundle: Any, *, case_id: str, ledger: InvestigationLedger,
    files: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate all references against verified/staged files and ledger bindings.

    Callers must first verify the export signature, file inventory, and ledger.
    This function also runs on the staged export before any ZIP is written.
    The returned index is a detached canonical snapshot for reconstruction.
    """
    import json

    try:
        raw = canonical_json_bytes(bundle)
        _require(len(raw) <= MAX_PROVENANCE_BYTES, "provenance exceeds size limit")
        bundle = json.loads(raw)
        return _validate(bundle, case_id=case_id, ledger=ledger, files=files)
    except ProvenanceError:
        raise
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        raise ProvenanceError("malformed provenance profile") from exc


def _validate(bundle, *, case_id, ledger, files):
    expected_fields = {"schema", "case_id", "content_policy", "content_review", "comparisons", *_TYPES}
    _require(isinstance(bundle, dict) and set(bundle) == expected_fields, "invalid provenance profile fields")
    _require(bundle["schema"] == PROVENANCE_SCHEMA, "unsupported provenance schema")
    _require(_text(case_id) and bundle["case_id"] == case_id == ledger.case_id, "provenance case mismatch")
    policy = bundle["content_policy"]
    _require(policy in {"references-only", "reviewed-content"}, "unsupported content policy")
    if policy == "references-only":
        _require(bundle["content_review"] is None, "unexpected content review")
    else:
        review = bundle["content_review"]
        _require(isinstance(review, dict) and set(review) == {"reviewer", "reviewed_at"}, "content review required")
        _require(_text(review["reviewer"]), "content reviewer required")
        utc_timestamp(review["reviewed_at"])

    index = {}
    by_kind = {}
    count = 0
    for kind, (cls, id_field, _) in _TYPES.items():
        rows = bundle[kind]
        _require(isinstance(rows, list), "provenance collection must be an array")
        count += len(rows)
        _require(count <= MAX_RECORDS, "provenance record limit exceeded")
        by_kind[kind] = {}
        for row in rows:
            keys = {"schema", "record", "record_hash"}
            if kind == "artifacts":
                keys.add("path")
            if kind == "ai_records":
                keys.add("output_sha256")
            _require(isinstance(row, dict) and set(row) == keys, "invalid provenance record envelope")
            _require(row["schema"] == f"ai-dfir/provenance/{kind}/v1.7", "record schema mismatch")
            rec = row["record"]
            _require(isinstance(rec, dict) and set(rec) == {f.name for f in fields(cls)}, "invalid typed record fields")
            _require(rec["case_id"] == case_id, "record case mismatch")
            nullable = {"media_type", "source_name", "acquired_at", "classification", "model_version", "request_id", "policy_config_id", "transformation", "transformation_version", "created_at", "rationale"}
            if kind == "relationships":
                nullable.add("actor")
            for key, value in rec.items():
                if key in {"metadata", "structured_output", "confidence", "evidence_refs", "retrieval_refs", "tool_calls", "output_refs"}:
                    continue
                _require((value is None and key in nullable) or _text(value), "invalid typed text field")
            _require(_digest(row["record_hash"]) and row["record_hash"] == record_hash(row), "record hash mismatch")
            ident = rec[id_field] if id_field else row["record_hash"]
            _require(_text(ident) and ident not in index, "duplicate or invalid record identifier")
            for key in ("timestamp", "acquired_at", "created_at"):
                if key in rec and rec[key] is not None:
                    utc_timestamp(rec[key])
            for key in ("evidence_refs", "retrieval_refs", "tool_calls", "output_refs"):
                if key in rec:
                    refs = rec[key]
                    _require(isinstance(refs, list) and all(_text(v) for v in refs), "invalid reference list")
                    _require(len(refs) == len(set(refs)), "duplicate references")
            _check_content(rec)
            index[ident] = {"kind": kind, **row}
            by_kind[kind][ident] = rec

    artifacts = by_kind["artifacts"]
    paths = set()
    for ident, rec in artifacts.items():
        path = index[ident]["path"]
        _require(_path(path) and path != PROVENANCE_PATH and not path.startswith("00_case/v17/"), "invalid evidence path")
        _require(path not in paths, "duplicate evidence path")
        paths.add(path)
        _require(_digest(rec["sha256"]), "invalid evidence content digest")
        _require(path in files and files[path]["sha256"] == rec["sha256"], "missing or mismatched evidence bytes")
        _require(isinstance(rec["metadata"], dict), "artifact metadata must be an object")

    # Kahn's algorithm rejects cycles without recursive traversal of hostile data.
    edges = {ident: set() for ident in artifacts}
    degrees = {ident: 0 for ident in artifacts}
    for rec in by_kind["relationships"].values():
        parent, child = rec["parent_artifact_id"], rec["child_artifact_id"]
        _require(_text(parent) and _text(child) and parent in artifacts and child in artifacts, "dangling lineage reference")
        _require(parent != child and _text(rec["relationship_type"]), "invalid evidence relationship")
        _require(isinstance(rec["metadata"], dict), "relationship metadata must be an object")
        if (rec["transformation"], rec["transformation_version"]) == ("v17_log_analytics_context.normalize", "1.7"):
            meta = rec["metadata"]
            _require(set(meta) == {"input_format", "context_artifact_id"}
                     and meta["input_format"] in ("workspace-post", "workspace-get"),
                     "unsupported query context replay configuration")
            context = meta["context_artifact_id"]
            _require(_text(context) and context in artifacts and context not in {parent, child},
                     "missing or invalid query context artifact reference")
            # Context is a second derivation input, subject to the same cycle
            # checks as the primary response input. It cannot be the output.
            if child not in edges[context]:
                edges[context].add(child)
                degrees[child] += 1
        if child not in edges[parent]:
            edges[parent].add(child)
            degrees[child] += 1
    queue = deque(k for k, v in degrees.items() if v == 0)
    visited = 0
    while queue:
        parent = queue.popleft()
        visited += 1
        for child in edges[parent]:
            degrees[child] -= 1
            if degrees[child] == 0:
                queue.append(child)
    _require(visited == len(artifacts), "cyclic evidence lineage")

    ai = by_kind["ai_records"]
    tools = by_kind["tool_records"]
    for ident, item in index.items():
        rec, kind = item["record"], item["kind"]
        for key in ("evidence_refs", "retrieval_refs", "output_refs"):
            _require(all(ref in artifacts for ref in rec.get(key, [])), "dangling evidence reference")
        if kind == "ai_records":
            _require(_text(rec["provider"]) and _text(rec["model"]), "AI provider and model required")
            utc_timestamp(rec["timestamp"])
            _require(isinstance(rec["structured_output"], dict), "structured output must be an object")
            if policy == "references-only":
                _require(not rec["structured_output"], "inline output requires content review")
            confidence = rec["confidence"]
            _require(confidence is None or (type(confidence) in {int, float} and 0 <= confidence <= 1), "invalid confidence")
            expected_output = sha256_object(rec["structured_output"]) if rec["structured_output"] else None
            _require(item["output_sha256"] == expected_output, "recorded output digest mismatch")
            _require(all(ref in tools and tools[ref]["invocation_id"] == ident for ref in rec["tool_calls"]), "unbound AI tool call")
        elif kind == "tool_records":
            invocation = rec["invocation_id"]
            _require(_text(invocation) and invocation in ai and ident in ai[invocation]["tool_calls"], "unbound tool invocation")
            _require(_text(rec["tool_name"]) and _text(rec["actor"]), "tool identity required")
            _require(rec["status"] in {"succeeded", "failed", "unknown"}, "unsupported tool status")
            _require(_digest(rec["arguments_sha256"]), "invalid tool arguments digest")
        elif kind == "analyst_decisions":
            target = rec["target_id"]
            _require(_text(target) and target in index and index[target]["kind"] in {"artifacts", "ai_records", "tool_records"}, "dangling decision target")
            _require(_text(rec["analyst_id"]), "analyst identity required")
            _require(rec["disposition"] in {"confirmed", "rejected", "accepted_with_qualification", "escalated", "containment_approved", "containment_denied", "closed"}, "unsupported analyst disposition")
            _require(rec["rationale"] is None or _text(rec["rationale"]), "invalid decision rationale")
            if policy == "references-only":
                _require(rec["rationale"] is None, "inline rationale requires content review")

    bound = set()
    for event in ledger.events:
        payload = event.payload
        _require(isinstance(payload, dict), "invalid ledger payload")
        if "provenance_type" not in payload:
            continue
        _require(set(payload) == {"provenance_type", "record_id", "record_hash"}, "invalid ledger record binding")
        ident = payload["record_id"]
        _require(_text(ident) and ident in index and ident not in bound, "missing or duplicate ledger record binding")
        item = index[ident]
        kind, rec = item["kind"], item["record"]
        _require(payload["provenance_type"] == kind and event.event_type == _TYPES[kind][2], "ledger record type mismatch")
        _require(payload["record_hash"] == item["record_hash"], "ledger record hash mismatch")
        utc_timestamp(event.timestamp)
        _require(_text(event.actor), "ledger actor required")
        if rec.get("timestamp") is not None:
            _require(utc_timestamp(event.timestamp) == utc_timestamp(rec["timestamp"]), "ledger record timestamp mismatch")
        expected_actor = rec.get("analyst_id") if kind == "analyst_decisions" else rec.get("actor")
        if expected_actor is not None:
            _require(event.actor == expected_actor, "ledger record actor mismatch")
        item["ledger_sequence"] = event.sequence
        bound.add(ident)
    _require(bound == set(index), "provenance record missing ledger commitment")

    comparisons = bundle["comparisons"]
    _require(isinstance(comparisons, list) and len(comparisons) <= MAX_RECORDS, "invalid comparisons")
    seen = set()
    for comparison in comparisons:
        _require(isinstance(comparison, dict) and set(comparison) == {"original", "comparison"}, "invalid comparison fields")
        original, later = comparison["original"], comparison["comparison"]
        _require(_text(original) and _text(later) and original in ai and later in ai and original != later, "invalid comparison invocations")
        _require((original, later) not in seen, "duplicate comparison")
        seen.add((original, later))
        _require(utc_timestamp(ai[later]["timestamp"]) >= utc_timestamp(ai[original]["timestamp"]), "comparison precedes original invocation")
    return index
