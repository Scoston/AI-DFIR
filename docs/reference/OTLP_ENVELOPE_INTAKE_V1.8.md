# OTLP Trace/Log Envelope Intake — AI-DFIR v1.8

Status: **development profile; repository-controlled qualification only**

## Purpose

AI-DFIR v1.8 can ingest bounded OpenTelemetry Protocol (OTLP) JSON trace and log envelopes while preserving the source envelope and the resource/scope context around each record. Trace envelopes can feed the existing OpenTelemetry GenAI adapter and AER reconstruction pipeline. Log records can be correlated to observed trace/span identifiers without treating that identifier match as proof of causality.

The current contract is anchored to OTLP specification **1.11.0**, where traces and logs are stable signals.

## Supported input profile

`v18_otlp_envelope.py` currently supports one JSON-encoded OTLP envelope at a time:

- traces: `resourceSpans -> scopeSpans -> spans`;
- logs: `resourceLogs -> scopeLogs -> logRecords`.

Inputs may be supplied as observed UTF-8 JSON bytes or as an already-parsed Python object. When bytes are supplied, the exact envelope bytes are retained and `source_bytes_preserved` is true. When an object is supplied, AI-DFIR retains its deterministic canonical JSON representation and keeps `source_bytes_preserved` false because the original serialization was not observed.

Current bounded limits are:

- 64 MiB per envelope;
- 2,048 resource groups;
- 8,192 scope groups;
- 50,000 spans per trace envelope;
- 100,000 log records per log envelope.

Those are parser safety bounds, not production performance claims.

## Trace intake

Trace intake preserves:

- complete source envelope bytes/hash/size;
- OTLP resource attributes and schema URL;
- instrumentation scope name/version/attributes/schema URL;
- each span's original object as a canonical, hash-bound OpenTelemetry GenAI adapter input;
- trace ID, span ID and parent span ID;
- selected GenAI semantic-convention fields through the existing v1.8 adapter;
- explicit diagnostics for missing trace/span identifiers and unknown top-level fields.

Non-empty OTLP trace IDs must be 32 hexadecimal characters and non-empty span/parent IDs must be 16 hexadecimal characters. Duplicate OTLP attribute keys fail closed rather than being silently overwritten.

Validation replays every retained span through the OpenTelemetry GenAI adapter and compares the result with the stored adapted record. It also re-parses the retained source envelope and verifies that each span plus its resource/scope/index context matches the derived intake record. A caller cannot replace derived context, normalized GenAI fields or a retained span and simply recompute the outer record hash.

## Log intake

Log intake retains:

- complete source envelope bytes/hash/size;
- resource and instrumentation-scope context;
- exact canonical log-record bytes/hash/size;
- trace and span IDs when present;
- OTLP time fields;
- severity number/text;
- event name and flags;
- body and attributes.

Validation replays each retained log record from its retained bytes and context and verifies that the resulting record matches the import. It also verifies that the set of log/context bindings matches the retained OTLP source envelope.

## AER reconstruction bridge

`reconstruct_imported_trace()` selects one trace ID from an imported OTLP trace envelope and passes only that trace's adapted spans to the existing deterministic `v18_runtime_reconstruction.py` pipeline.

The returned wrapper binds:

- the OTLP trace-import record hash;
- the source envelope evidence reference;
- the selected trace ID;
- resource/scope/index context for each selected adapted span;
- the resulting AER reconstruction bundle.

Resource/scope context is retained outside the AER graph rather than rewriting the original span evidence. This preserves the distinction between source evidence and derived contextual metadata.

## Trace/log correlation

`correlate_trace_logs()` classifies each imported log as one of:

- `matched_trace_and_span`;
- `matched_trace_only`;
- `trace_present_span_missing`;
- `external_or_unobserved_trace`;
- `unlinked`.

The report is bound to both the trace-import and log-import record hashes.

An identifier match is **correlation evidence only**. The report keeps `log_generated_by_span_proven`, `business_causality_proven`, and `collection_complete` false.

## Synthetic qualification

`scripts/qualify_otlp_envelope_v18.py` creates a deterministic bounded population and exercises trace intake, log intake, identifier correlation, and one selected-trace AER reconstruction.

The dedicated `OTLP v1.8 Qualification` workflow currently exercises:

- 2,048 spans;
- 4,096 log records;
- 8 traces.

The qualification retains a hash-bound report and the generated trace/log envelope hashes for 14 days.

A passing run establishes that this synthetic population was accepted by the current bounded intake/reconstruction profile. It does **not** establish production scale, collector interoperability, transport completeness, telemetry authenticity, or live-environment performance.

## Deliberately unsupported in this profile

The current implementation does not yet claim native parsing/qualification for:

- binary Protobuf OTLP payloads;
- OTLP/gRPC transport capture;
- gzip HTTP transport decoding/custody;
- multi-envelope OTLP File Exporter JSONL files;
- live collector/exporter interoperability;
- metrics or profiles signals.

These should be added as separately bounded/versioned profiles rather than silently treating every OpenTelemetry representation as equivalent.

## Evidence/claim boundary

OTLP ingestion does not establish that telemetry collection was complete or that the source was authentic. Trace parentage and trace/log ID matches do not prove model intent or business causality. Missing spans/logs remain missing evidence, not evidence that an event did not occur.

The profile therefore keeps the following false unless separately established by additional evidence:

- telemetry authenticity;
- collection completeness;
- transport-delivery completeness;
- semantic-meaning completeness;
- log-to-span causality;
- business causality;
- intent causality;
- private model reasoning capture.

## Version anchors

- OTLP specification contract: 1.11.0
- OpenTelemetry GenAI semantic-convention version: supplied by the evidence source/operator and retained per import
- AER/reconstruction profile: AI-DFIR v1.8 development
