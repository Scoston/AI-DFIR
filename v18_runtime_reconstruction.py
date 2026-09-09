"""Deterministic multi-span OpenTelemetry GenAI -> AER reconstruction.

This module reconstructs observable trace structure. Parent/span relationships are
correlation evidence, not proof of model intent or real-world causation.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime
from typing import Any, Iterable

import v18_agent_execution_record as aer
import v18_otel_genai as otel

SCHEMA = "ai-dfir/otel-aer-reconstruction/v1.8"
MAX_SPANS = 10_000
MAX_RAW_BYTES = 32 * 1024 * 1024


def _dt(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("observed_at is required")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid observed_at timestamp") from exc


def _span_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (str(record.get("trace_id") or ""), str(record.get("span_id") or ""), str(record.get("record_sha256") or ""))


def _raw_ref(record: dict[str, Any]) -> dict[str, Any]:
    raw = record["raw_span"]
    trace = record.get("trace_id") or "unknown-trace"
    span = record.get("span_id") or record["record_sha256"][:16]
    return aer.evidence_ref("otel-genai-span", raw["sha256"], raw["size"],
                            locator=f"otel:{trace}:{span}", observed_at=record["observed_at"])


def _base_kind(attrs: dict[str, Any]) -> str:
    if attrs.get("gen_ai.agent.id") or attrs.get("gen_ai.agent.name"):
        return "agent"
    if attrs.get("gen_ai.workflow.name") or attrs.get("gen_ai.operation.name"):
        return "workflow"
    return "unknown"


def _base_attributes(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record["normalized_genai"]
    keep = (
        "gen_ai.agent.id", "gen_ai.agent.name", "gen_ai.agent.version", "gen_ai.agent.description",
        "gen_ai.conversation.id", "gen_ai.workflow.name", "gen_ai.operation.name",
        "gen_ai.system_instructions", "gen_ai.input.messages", "gen_ai.output.messages",
    )
    out = {key: deepcopy(attrs[key]) for key in keep if key in attrs}
    out.update({
        "otel_trace_id": record.get("trace_id"),
        "otel_span_id": record.get("span_id"),
        "otel_parent_span_id": record.get("parent_span_id"),
        "otel_span_name": record.get("span_name"),
        "semantic_conventions_version": record["semantic_conventions_version"],
        "unmapped_genai_attributes": list(record.get("unmapped_attribute_names", [])),
    })
    return out


def _cycle(parent_by_span: dict[str, str]) -> list[str] | None:
    """Return a deterministic cycle path when malformed parent pointers cycle."""
    done: set[str] = set()
    for start in sorted(parent_by_span):
        if start in done:
            continue
        order: list[str] = []
        pos: dict[str, int] = {}
        cur = start
        while cur in parent_by_span:
            if cur in pos:
                return order[pos[cur]:] + [cur]
            if cur in done:
                break
            pos[cur] = len(order)
            order.append(cur)
            cur = parent_by_span[cur]
        done.update(order)
    return None


def reconstruct_trace(adapted_spans: Iterable[dict[str, Any]], *, record_id: str) -> dict[str, Any]:
    spans = [deepcopy(item) for item in adapted_spans]
    if not spans:
        raise ValueError("at least one adapted span is required")
    if len(spans) > MAX_SPANS:
        raise ValueError("span count exceeds reconstruction bound")

    total_raw = 0
    for item in spans:
        otel.validate(item)
        raw = item["raw_span"]
        base64.b64decode(raw["base64"], validate=True)
        total_raw += raw["size"]
    if total_raw > MAX_RAW_BYTES:
        raise ValueError("raw span bytes exceed reconstruction bound")

    spans.sort(key=_span_key)
    trace_ids = {item.get("trace_id") for item in spans}
    if None in trace_ids or "" in trace_ids or len(trace_ids) != 1:
        raise ValueError("reconstruct_trace requires exactly one non-empty trace_id")
    trace_id = next(iter(trace_ids))

    by_id: dict[str, dict[str, Any]] = {}
    synthetic_ids: dict[str, str] = {}
    for item in spans:
        span_id = item.get("span_id")
        if span_id:
            if span_id in by_id:
                raise ValueError(f"duplicate span_id: {span_id}")
            by_id[span_id] = item
        else:
            synthetic_ids[item["record_sha256"]] = f"missing-{item['record_sha256'][:16]}"

    parent_by_span: dict[str, str] = {}
    for span_id, item in by_id.items():
        parent = item.get("parent_span_id")
        if parent:
            parent_by_span[span_id] = parent
    cycle = _cycle(parent_by_span)
    if cycle:
        raise ValueError("cyclic parent_span_id graph: " + " -> ".join(cycle))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    raw_refs: list[dict[str, Any]] = []
    base_node_by_span: dict[str, str] = {}
    diagnostics: dict[str, Any] = {
        "trace_id": trace_id,
        "span_count": len(spans),
        "raw_bytes": total_raw,
        "orphan_parent_span_ids": [],
        "missing_span_id_record_sha256": [],
        "unmapped_span_ids": [],
        "semantic_conventions_versions": sorted({item["semantic_conventions_version"] for item in spans}),
        "causal_links_inferred": False,
    }

    for item in spans:
        ref = _raw_ref(item)
        raw_refs.append(ref)
        span_id = item.get("span_id") or synthetic_ids[item["record_sha256"]]
        base_id = f"otel-span:{span_id}"
        base_node_by_span[span_id] = base_id
        attrs = item["normalized_genai"]
        kind = _base_kind(attrs)
        if kind == "unknown":
            diagnostics["unmapped_span_ids"].append(span_id)
        if item.get("span_id") is None:
            diagnostics["missing_span_id_record_sha256"].append(item["record_sha256"])
        nodes.append(aer.node(base_id, kind, item["observed_at"],
                              attributes=_base_attributes(item), evidence_refs=[ref]))

        if "gen_ai.retrieval.query.text" in attrs or "gen_ai.retrieval.documents" in attrs:
            retrieval_id = f"{base_id}:retrieval"
            nodes.append(aer.node(retrieval_id, "retrieval", item["observed_at"], attributes={
                "query": deepcopy(attrs.get("gen_ai.retrieval.query.text")),
                "documents": deepcopy(attrs.get("gen_ai.retrieval.documents")),
                "source": "opentelemetry-genai",
            }, evidence_refs=[ref]))
            edges.append(aer.edge(f"edge:{base_id}:retrieval", base_id, retrieval_id,
                                  "correlated_with", evidence_refs=[ref], confidence="observed",
                                  unknown_fields=["causal_influence", "retrieval_completeness"]))

        if "gen_ai.tool.name" in attrs or "gen_ai.tool.type" in attrs:
            tool_id = f"{base_id}:tool"
            nodes.append(aer.node(tool_id, "tool", item["observed_at"], attributes={
                "name": deepcopy(attrs.get("gen_ai.tool.name")),
                "type": deepcopy(attrs.get("gen_ai.tool.type")),
                "source": "opentelemetry-genai",
            }, evidence_refs=[ref]))
            edges.append(aer.edge(f"edge:{base_id}:tool", base_id, tool_id,
                                  "correlated_with", evidence_refs=[ref], confidence="observed",
                                  unknown_fields=["tool_invocation_occurred", "tool_side_effects"]))

        model_name = attrs.get("gen_ai.response.model") or attrs.get("gen_ai.request.model")
        if model_name is not None or attrs.get("gen_ai.provider.name") is not None:
            model_id = f"{base_id}:model"
            nodes.append(aer.node(model_id, "model", item["observed_at"], attributes={
                "request_model": deepcopy(attrs.get("gen_ai.request.model")),
                "response_model": deepcopy(attrs.get("gen_ai.response.model")),
                "provider": deepcopy(attrs.get("gen_ai.provider.name")),
                "source": "opentelemetry-genai",
            }, evidence_refs=[ref]))
            edges.append(aer.edge(f"edge:{base_id}:model", base_id, model_id,
                                  "correlated_with", evidence_refs=[ref], confidence="observed",
                                  unknown_fields=["model_execution_causality"]))

    orphan_pairs: list[tuple[str, str]] = []
    for span_id, item in sorted(by_id.items()):
        parent = item.get("parent_span_id")
        if not parent:
            continue
        if parent not in by_id:
            orphan_pairs.append((span_id, parent))
            continue
        ref = _raw_ref(item)
        edges.append(aer.edge(f"edge:otel-parent:{parent}:{span_id}",
                              base_node_by_span[parent], base_node_by_span[span_id],
                              "correlated_with", evidence_refs=[ref], confidence="observed",
                              unknown_fields=["business_causality", "intent_causality"]))
    diagnostics["orphan_parent_span_ids"] = [
        {"span_id": span_id, "missing_parent_span_id": parent} for span_id, parent in orphan_pairs
    ]

    nodes.sort(key=lambda n: n["node_id"])
    edges.sort(key=lambda e: e["edge_id"])
    raw_refs.sort(key=lambda r: (r["sha256"], r.get("locator", "")))
    start = min(spans, key=lambda x: _dt(x["observed_at"]))["observed_at"]
    end = max(spans, key=lambda x: _dt(x["observed_at"]))["observed_at"]
    semconv = ",".join(diagnostics["semantic_conventions_versions"])
    record = aer.build_record(record_id, start, ended_at=end, nodes=nodes, edges=edges,
                              source_versions={"otel_genai_semconv": semconv, "otel_adapter": otel.SCHEMA},
                              raw_evidence=raw_refs,
                              claims={"complete_context_captured": False, "causal_intent_proven": False})
    bundle = {
        "schema": SCHEMA,
        "trace_id": trace_id,
        "aer": record,
        "diagnostics": diagnostics,
        "claims": {
            "trace_structure_reconstructed": True,
            "trace_complete": False,
            "business_causality_proven": False,
            "intent_causality_proven": False,
            "private_reasoning_captured": False,
        },
    }
    bundle["bundle_sha256"] = aer.sha256_bytes(aer.canonical_bytes(bundle))
    validate_reconstruction(bundle)
    return bundle


def validate_reconstruction(bundle: dict[str, Any]) -> bool:
    if not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA:
        raise ValueError("unsupported reconstruction schema")
    aer.validate_record(bundle.get("aer"))
    diagnostics = bundle.get("diagnostics")
    if not isinstance(diagnostics, dict) or diagnostics.get("causal_links_inferred") is not False:
        raise ValueError("invalid reconstruction diagnostics")
    claims = bundle.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("claims missing")
    for key in ("trace_complete", "business_causality_proven", "intent_causality_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    digest = bundle.get("bundle_sha256")
    unsigned = deepcopy(bundle); unsigned.pop("bundle_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("reconstruction bundle hash mismatch")
    return True
