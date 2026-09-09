"""RAG and memory provenance for AI-DFIR v1.8."""
from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any, Iterable

from v18_agent_execution_record import canonical_bytes, sha256_bytes

RETRIEVAL_SCHEMA = "ai-dfir/retrieval-provenance/v1.8"
MEMORY_SCHEMA = "ai-dfir/memory-provenance/v1.8"
MAX_CONTENT_BYTES = 2 * 1024 * 1024


def _blob(content: bytes | None) -> dict[str, Any] | None:
    if content is None:
        return None
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("content must be bytes")
    content = bytes(content)
    if len(content) > MAX_CONTENT_BYTES:
        raise ValueError("content exceeds bounded provenance size")
    return {"sha256": sha256_bytes(content), "size": len(content), "base64": base64.b64encode(content).decode("ascii")}


def document(doc_id: str, chunk_id: str, *, content: bytes | None, score: float | None = None,
             rank: int | None = None, source_uri: str | None = None) -> dict[str, Any]:
    if not isinstance(doc_id, str) or not doc_id or not isinstance(chunk_id, str) or not chunk_id:
        raise ValueError("doc_id and chunk_id are required")
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float))):
        raise ValueError("score must be numeric")
    if rank is not None and (isinstance(rank, bool) or not isinstance(rank, int) or rank < 0):
        raise ValueError("rank must be a non-negative integer")
    return {"document_id": doc_id, "chunk_id": chunk_id, "content": _blob(content),
            "score": score, "rank": rank, "source_uri": source_uri}


def retrieval(query: bytes, *, observed_at: str, index_id: str, index_revision: str,
              embedding_model: dict[str, str], returned_documents: Iterable[dict[str, Any]],
              candidate_documents: Iterable[dict[str, Any]] = (), reranker: dict[str, str] | None = None) -> dict[str, Any]:
    if not isinstance(query, (bytes, bytearray)):
        raise TypeError("query must be bytes")
    if not index_id or not index_revision:
        raise ValueError("index_id and index_revision are required")
    if not isinstance(embedding_model, dict) or not embedding_model.get("name"):
        raise ValueError("embedding_model.name is required")
    record = {"schema": RETRIEVAL_SCHEMA, "observed_at": observed_at, "query": _blob(bytes(query)),
              "index_id": index_id, "index_revision": index_revision,
              "embedding_model": deepcopy(embedding_model), "reranker": deepcopy(reranker),
              "candidate_documents": [deepcopy(x) for x in candidate_documents],
              "returned_documents": [deepcopy(x) for x in returned_documents],
              "claims": {"retrieval_complete": False, "index_authenticity_verified": False,
                         "content_semantically_correct": False}}
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    validate_retrieval(record)
    return record


def memory_event(operation: str, *, memory_id: str, observed_at: str, source_execution_id: str,
                 before: bytes | None, after: bytes | None, input_content: bytes | None = None,
                 namespace: str | None = None, ttl: str | None = None) -> dict[str, Any]:
    if operation not in {"read", "write", "delete", "expire"}:
        raise ValueError("unsupported memory operation")
    if not memory_id or not source_execution_id:
        raise ValueError("memory_id and source_execution_id are required")
    record = {"schema": MEMORY_SCHEMA, "operation": operation, "memory_id": memory_id,
              "namespace": namespace, "observed_at": observed_at, "source_execution_id": source_execution_id,
              "before": _blob(before), "input": _blob(input_content), "after": _blob(after), "ttl": ttl,
              "claims": {"memory_store_complete": False, "memory_authenticity_verified": False,
                         "causal_effect_proven": False}}
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    validate_memory(record)
    return record


def _validate_blob(blob: dict[str, Any] | None) -> None:
    if blob is None:
        return
    raw = base64.b64decode(blob.get("base64", ""), validate=True)
    if blob.get("size") != len(raw) or blob.get("sha256") != sha256_bytes(raw):
        raise ValueError("content custody mismatch")


def _validate_hash(record: dict[str, Any]) -> None:
    digest = record.get("record_sha256")
    unsigned = deepcopy(record); unsigned.pop("record_sha256", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("record hash mismatch")


def validate_retrieval(record: dict[str, Any]) -> bool:
    if record.get("schema") != RETRIEVAL_SCHEMA:
        raise ValueError("unsupported retrieval schema")
    _validate_blob(record.get("query"))
    for key in ("candidate_documents", "returned_documents"):
        docs = record.get(key)
        if not isinstance(docs, list):
            raise ValueError(f"{key} must be an array")
        for doc in docs:
            if not isinstance(doc, dict) or not doc.get("document_id") or not doc.get("chunk_id"):
                raise ValueError("invalid retrieval document")
            _validate_blob(doc.get("content"))
    _validate_hash(record)
    return True


def validate_memory(record: dict[str, Any]) -> bool:
    if record.get("schema") != MEMORY_SCHEMA or record.get("operation") not in {"read", "write", "delete", "expire"}:
        raise ValueError("unsupported memory schema/operation")
    for key in ("before", "input", "after"):
        _validate_blob(record.get(key))
    _validate_hash(record)
    return True
