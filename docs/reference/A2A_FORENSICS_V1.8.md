# A2A Protocol Forensics — AI-DFIR v1.8

Status: **development profile; repository-controlled synthetic qualification only**

## Purpose

AI-DFIR v1.8 captures observable Agent2Agent (A2A) protocol activity and binds it into the Agent Execution Record (AER). The profile is intended to help an investigator reconstruct which agents communicated, which protocol operation was observed, which task/message/artifact objects crossed the boundary, and which evidence remains unknown.

This profile does not attempt to infer private model reasoning or subjective intent. It also does not treat an Agent Card, task identifier, transport session, or credential fingerprint as proof that a request was authorized.

## Version contract

The current profile targets the released A2A `1.0.0` protocol line and records the per-request `A2A-Version` service parameter.

For this profile:

- `A2A-Version: 1.0` is recorded as a profile match;
- another syntactically valid `Major.Minor` value is retained but not treated as a 1.0 match;
- a missing or empty version header is explicitly recorded using the protocol's legacy `0.3` default behavior rather than silently assuming 1.0;
- `A2A-Extensions` values are retained as an inventory of requested extension URIs.

Version observation is evidence of the requested protocol contract. It is not proof that every peer behavior conformed to that contract.

## Supported bindings

The repository-controlled v1.8 profile currently supports:

- **JSON-RPC 2.0 over HTTP(S)** using the A2A 1.0 PascalCase operations such as `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, push-notification configuration operations, and `GetExtendedAgentCard`;
- **HTTP+JSON** with route-to-operation observations for `/message:send`, `/message:stream`, task retrieval/list/cancel/subscribe routes, push-notification configuration routes, and `/extendedAgentCard`.

The gRPC binding is deliberately rejected by this development profile. Binary protobuf framing, HTTP/2 transport details, and gRPC metadata require a separate bounded capture and qualification profile before AI-DFIR should claim support.

## Request/response custody

`v18_a2a_forensics.py` preserves exact request and response body bytes with:

- SHA-256;
- byte length;
- base64 representation;
- capture timestamp;
- binding, method, path and response status;
- normalized safe header values;
- fingerprints for sensitive credential-bearing headers.

The strict JSON parser rejects duplicate object keys and non-finite JSON values. JSON-RPC capture additionally requires `jsonrpc: "2.0"` when a JSON-RPC body is present.

### Credential-header handling

Reusable HTTP credential header values are **not** retained in plaintext by the normalized header record. Examples include `Authorization`, cookies and common API-key headers. Instead AI-DFIR records, per observed value:

- credential scheme when present;
- SHA-256 of the exact header value;
- encoded length.

This allows investigators to compare whether the same credential material was observed without turning the normalized record into a reusable credential store.

This protection applies to recognized HTTP credential headers only. **A2A protocol bodies are intentionally preserved exactly as evidence and may themselves contain secrets, tokens, push-notification configuration data, sensitive user content, or regulated information.** Operators must therefore apply evidence-store encryption, access control, minimization, retention and legal-hold policy appropriate to the captured data.

## Agent Card observation and v1.3 trust

`observe_agent_card()` can retain Agent Card bytes and summarize:

- card name and agent version;
- provider metadata;
- supported interface URL, binding, protocol version and tenant information;
- declared skill IDs;
- number of presented signatures.

The v1.8 observation module **does not independently verify Agent Card JWS signatures or provider trust**.

AI-DFIR already models Agent Card signature verification, enterprise trust, transport identity, key rotation and delegation trust in [`A2A_TRUST_ARCHITECTURE_V1.3.md`](../../A2A_TRUST_ARCHITECTURE_V1.3.md). An investigator can correlate the v1.8 `agent_card_sha256` with that separately acquired trust evidence, but hash equality does not itself establish that the card or provider was trusted at incident time.

The propositions remain separate:

1. these Agent Card bytes were observed;
2. a signature over those bytes/canonical payload is cryptographically valid;
3. the signer/key/provider was trusted under the applicable historical policy;
4. the transport peer was authenticated as expected;
5. the task/message was authorized under delegated authority.

## First-class AER objects

AER now includes first-class node kinds for:

- `task`;
- `message`;
- `artifact`.

For each retained A2A exchange, the reconstruction can create:

- client and server `agent` nodes;
- a `protocol` exchange node;
- `context` nodes for observed A2A context IDs;
- `task` observations and task states;
- request/response `message` observations and roles;
- `artifact` observations and artifact IDs.

The implementation uses evidence-backed relationships such as `communicated_with`, `provided_context`, `produced`, `observed`, and `correlated_with`.

Repeated task IDs are correlated across observations, but task state changes are **not** automatically labeled causal transitions. A matching task ID can support reconstruction without proving that every intermediate state or message was captured.

The v1.8 A2A module deliberately does not create a `delegated_authority` edge merely because an A2A request was observed. Delegated identity and authority require separate evidence such as principal/token lineage, authorization policy, approval state, transport identity, and target-side audit evidence.

## Streaming evidence

A2A streaming responses are captured from Server-Sent Events (SSE). The bounded profile:

- retains the complete observed stream bytes and SHA-256;
- parses `data:` payloads in sequence;
- accepts one A2A `StreamResponse` member per event (`task`, `message`, `statusUpdate`, or `artifactUpdate`);
- records each event sequence, type and payload hash;
- rejects events containing multiple union members;
- limits a retained stream to 32 MiB and 10,000 parsed events.

A captured SSE stream does not prove delivery completeness. Connection loss, resume behavior, proxy buffering, client-side loss and missed earlier events remain possible unless independently established. Therefore `delivery_complete` and `reconnection_gap_free` remain false.

## Bounds

The current repository profile enforces:

| Item | Bound |
|---|---:|
| request body | 8 MiB |
| response body | 8 MiB |
| normalized headers | 256 |
| A2A exchanges per AER build | 10,000 |
| SSE stream bytes | 32 MiB |
| SSE events | 10,000 |

These are implementation/qualification boundaries, not recommended production retention limits.

## Synthetic qualification

`.github/workflows/a2a-v18-qualification.yml` runs a deterministic repository-controlled campaign with:

- 512 A2A exchanges;
- 8 synthetic agent identities;
- an even split between JSON-RPC and HTTP+JSON capture;
- paired working/completed task observations;
- messages, artifacts and context IDs;
- synthetic `Authorization` values that must remain fingerprint-only in normalized headers;
- 128 SSE events;
- A2A-to-AER reconstruction and hash binding;
- retained qualification receipt, sample exchange and AER summary for 14 days.

A passing campaign establishes that this bounded synthetic profile behaved as tested in the GitHub Actions environment. It does **not** establish:

- A2A protocol certification or full conformance;
- live interoperability with a named A2A SDK/server;
- gRPC support;
- Agent Card/provider trust;
- transport authentication;
- request authorization;
- complete task history;
- production-scale qualification.

## Claim boundaries

The A2A v1.8 development profile preserves these rules:

- **Observed communication is not authorization.** A request reaching a server does not prove it was allowed under enterprise policy.
- **Task IDs are correlation identifiers, not intent proofs.** Repeated IDs help join evidence but do not establish why an agent acted.
- **Agent Card observation is not Agent Card trust.** JWS validity and enterprise trust remain separate v1.3 evidence propositions.
- **Credential fingerprints are identity aids, not principal proof.** A matching hash shows matching retained header material, not who controlled it.
- **Protocol body custody is not source authenticity.** SHA-256 binds retained bytes; it does not prove who created or transmitted them.
- **Streaming capture is not completeness proof.** Missing or resumed SSE segments remain possible.
- **No hidden reasoning claim.** The profile captures observable protocol evidence only.

## External/live work still required

Repository code alone cannot establish live interoperability. Remaining external qualification includes:

- a named A2A 1.0 client and server/SDK pair;
- controlled authentication and historical Agent Card trust inputs;
- a live or staged gRPC/protobuf target if that binding is to be supported;
- TLS/identity observations appropriate to the deployment;
- provider-specific error/retry/cancellation/stream-resume behavior;
- authorized task/identity/authority evidence from real systems.

## Relevant files

- `v18_a2a_forensics.py`
- `tests/test_v18_a2a_forensics.py`
- `scripts/qualify_a2a_v18.py`
- `.github/workflows/a2a-v18-qualification.yml`
- `schemas/agent-execution-record-v1.8.schema.json`
- [`A2A_TRUST_ARCHITECTURE_V1.3.md`](../../A2A_TRUST_ARCHITECTURE_V1.3.md)
