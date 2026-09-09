#!/usr/bin/env python3
"""Synthetic bounded-population qualification for AI-DFIR v1.8 OTLP intake."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import v18_agent_execution_record as aer
import v18_otlp_envelope as otlp

SCHEMA = "ai-dfir/otlp-envelope-qualification/v1.8"
T = "2026-09-09T19:45:00Z"


def _attr(key: str, value: str) -> dict:
    return {"key": key, "value": {"stringValue": value}}


def _trace_payload(span_count: int, trace_count: int) -> tuple[dict, dict[str, list[str]]]:
    if span_count < trace_count or trace_count < 1:
        raise ValueError("span_count must be >= trace_count >= 1")
    traces = [f"{i + 1:032x}" for i in range(trace_count)]
    spans: list[dict] = []
    span_ids: dict[str, list[str]] = {trace: [] for trace in traces}
    for i in range(span_count):
        trace = traces[i % trace_count]
        span_id = f"{i + 1:016x}"
        ids = span_ids[trace]
        parent = ids[-1] if ids else ""
        ids.append(span_id)
        attrs = [
            _attr("gen_ai.operation.name", "invoke_agent" if not parent else "execute_tool"),
            _attr("gen_ai.agent.id", f"agent-{i % 17}"),
        ]
        if i % 5 == 0:
            attrs.append(_attr("gen_ai.tool.name", f"tool-{i % 23}"))
        if i % 7 == 0:
            attrs.append(_attr("gen_ai.retrieval.query.text", f"query-{i % 31}"))
        if i % 11 == 0:
            attrs.append(_attr("gen_ai.request.model", f"model-{i % 3}"))
        span = {
            "traceId": trace,
            "spanId": span_id,
            "name": f"operation-{i % 29}",
            "attributes": attrs,
        }
        if parent:
            span["parentSpanId"] = parent
        spans.append(span)
    return {
        "resourceSpans": [{
            "resource": {"attributes": [
                _attr("service.name", "ai-dfir-otlp-qualification"),
                _attr("deployment.environment.name", "synthetic"),
            ]},
            "scopeSpans": [{
                "scope": {"name": "ai-dfir.synthetic", "version": "1.8"},
                "spans": spans,
            }],
        }],
    }, span_ids


def _log_payload(log_count: int, span_ids: dict[str, list[str]]) -> dict:
    traces = sorted(span_ids)
    logs: list[dict] = []
    flat_pairs = [(trace, span) for trace in traces for span in span_ids[trace]]
    for i in range(log_count):
        mode = i % 5
        log: dict = {
            "timeUnixNano": str(1_000_000_000 + i),
            "severityNumber": 9,
            "severityText": "INFO",
            "body": {"stringValue": f"synthetic-log-{i}"},
            "attributes": [_attr("qualification.sequence", str(i))],
        }
        if mode == 0:
            trace, span = flat_pairs[i % len(flat_pairs)]
            log["traceId"] = trace
            log["spanId"] = span
        elif mode == 1:
            trace = traces[i % len(traces)]
            log["traceId"] = trace
        elif mode == 2:
            trace = traces[i % len(traces)]
            log["traceId"] = trace
            log["spanId"] = "ffffffffffffffff"
        elif mode == 3:
            log["traceId"] = "f" * 32
            log["spanId"] = "e" * 16
        logs.append(log)
    return {
        "resourceLogs": [{
            "resource": {"attributes": [_attr("service.name", "ai-dfir-otlp-qualification")]},
            "scopeLogs": [{
                "scope": {"name": "ai-dfir.synthetic.logs", "version": "1.8"},
                "logRecords": logs,
            }],
        }],
    }


def qualify(*, spans: int, logs: int, traces: int, out_dir: Path) -> dict:
    if spans < 1 or logs < 0 or traces < 1:
        raise ValueError("invalid qualification population")
    if spans > otlp.MAX_SPANS or logs > otlp.MAX_LOG_RECORDS:
        raise ValueError("qualification population exceeds importer bounds")
    trace_payload, span_ids = _trace_payload(spans, traces)
    log_payload = _log_payload(logs, span_ids)

    trace_bytes = json.dumps(trace_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    log_bytes = json.dumps(log_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    trace_import = otlp.import_trace_envelope(
        trace_bytes,
        semantic_conventions_version="qualification-profile",
        observed_at=T,
    )
    log_import = otlp.import_log_envelope(log_bytes, observed_at=T)
    correlation = otlp.correlate_trace_logs(trace_import, log_import)

    selected_trace = sorted(span_ids)[0]
    rebuilt = otlp.reconstruct_imported_trace(
        trace_import,
        trace_id=selected_trace,
        record_id="qualification/otlp-trace-0",
    )

    report = {
        "schema": SCHEMA,
        "profile": {
            "spans": spans,
            "logs": logs,
            "traces": traces,
            "selected_trace": selected_trace,
        },
        "trace_import_sha256": trace_import["record_sha256"],
        "log_import_sha256": log_import["record_sha256"],
        "correlation_report_sha256": correlation["report_sha256"],
        "reconstruction_record_sha256": rebuilt["record_sha256"],
        "observations": {
            "trace_raw_bytes_preserved": trace_import["claims"]["source_bytes_preserved"],
            "log_raw_bytes_preserved": log_import["claims"]["source_bytes_preserved"],
            "imported_spans": trace_import["diagnostics"]["span_count"],
            "imported_logs": log_import["diagnostics"]["log_record_count"],
            "trace_ids": len(trace_import["diagnostics"]["trace_ids"]),
            "selected_trace_spans": rebuilt["reconstruction"]["diagnostics"]["span_count"],
            "correlation_summary": correlation["summary"],
        },
        "claims": {
            "synthetic_population_accepted": True,
            "production_scale_qualified": False,
            "collector_interoperability_qualified": False,
            "telemetry_authenticity_verified": False,
            "collection_complete": False,
            "business_causality_proven": False,
        },
    }
    report["report_sha256"] = aer.sha256_bytes(aer.canonical_bytes(report))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "qualification-report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "trace-envelope-sha256.txt").write_text(
        aer.sha256_bytes(trace_bytes) + "\n", encoding="ascii"
    )
    (out_dir / "log-envelope-sha256.txt").write_text(
        aer.sha256_bytes(log_bytes) + "\n", encoding="ascii"
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spans", type=int, default=2048)
    ap.add_argument("--logs", type=int, default=4096)
    ap.add_argument("--traces", type=int, default=8)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()
    report = qualify(spans=args.spans, logs=args.logs, traces=args.traces, out_dir=args.out_dir)
    print(json.dumps({
        "status": "PASS",
        "spans": report["profile"]["spans"],
        "logs": report["profile"]["logs"],
        "traces": report["profile"]["traces"],
        "selected_trace_spans": report["observations"]["selected_trace_spans"],
        "report_sha256": report["report_sha256"],
        "production_scale_qualified": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
