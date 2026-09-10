#!/usr/bin/env python3
"""Bounded synthetic qualification for AI-DFIR v1.8 A2A forensic capture."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import v18_agent_execution_record as aer
import v18_a2a_forensics as a2a

SCHEMA = "ai-dfir/a2a-qualification/v1.8"
MAX_EXCHANGES = 2_000


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _exchange(index: int, agent_count: int) -> dict:
    client = f"client-{index % agent_count}"
    server = f"server-{(index + 1) % agent_count}"
    task = f"task-{index // 2:06d}"
    context = f"context-{index % 32:03d}"
    message = f"message-{index:06d}"
    artifact = f"artifact-{index:06d}"
    observed_at = f"2026-09-10T12:{30 + ((index // 60) % 20):02d}:{index % 60:02d}Z"
    auth = f"Bearer synthetic-secret-{index:06d}"

    if index % 2 == 0:
        request = {
            "jsonrpc": "2.0", "id": f"request-{index}", "method": "SendMessage",
            "params": {"message": {"messageId": message, "contextId": context,
                                     "role": "ROLE_USER", "parts": [{"text": f"work item {index}"}]}}
        }
        response = {
            "jsonrpc": "2.0", "id": f"request-{index}",
            "result": {"task": {"id": task, "contextId": context,
                                  "status": {"state": "TASK_STATE_WORKING"}}}
        }
        return a2a.capture_exchange(
            binding="JSONRPC", http_method="POST", path="/rpc",
            request_headers={"Content-Type": "application/json", "A2A-Version": "1.0",
                             "A2A-Extensions": "https://example.test/ext/trace", "Authorization": auth},
            request_body=_json(request), response_status=200,
            response_headers={"Content-Type": "application/json"}, response_body=_json(response),
            observed_at=observed_at, client_agent_id=client, server_agent_id=server,
            agent_card_sha256=aer.sha256_bytes(f"agent-card-{server}".encode()),
        )

    request = {
        "message": {"messageId": message, "contextId": context, "taskId": task,
                    "role": "ROLE_USER", "parts": [{"text": f"continue {index}"}]}
    }
    response = {
        "task": {"id": task, "contextId": context,
                 "status": {"state": "TASK_STATE_COMPLETED"},
                 "artifacts": [{"artifactId": artifact, "name": "result",
                                "parts": [{"text": f"result {index}"}]}],
                 "history": [{"messageId": f"reply-{index:06d}", "contextId": context,
                              "taskId": task, "role": "ROLE_AGENT",
                              "parts": [{"text": "complete"}]}]}
    }
    return a2a.capture_exchange(
        binding="HTTP+JSON", http_method="POST", path="/message:send",
        request_headers={"Content-Type": "application/a2a+json", "A2A-Version": "1.0",
                         "Authorization": auth}, request_body=_json(request), response_status=200,
        response_headers={"Content-Type": "application/a2a+json"}, response_body=_json(response),
        observed_at=observed_at, client_agent_id=client, server_agent_id=server,
        agent_card_sha256=aer.sha256_bytes(f"agent-card-{server}".encode()),
    )


def _stream(event_count: int) -> dict:
    chunks = []
    for index in range(event_count):
        if index == 0:
            payload = {"task": {"id": "stream-task", "contextId": "stream-context",
                                "status": {"state": "TASK_STATE_WORKING"}}}
        elif index == event_count - 1:
            payload = {"statusUpdate": {"taskId": "stream-task", "contextId": "stream-context",
                                        "status": {"state": "TASK_STATE_COMPLETED"}}}
        else:
            payload = {"artifactUpdate": {"taskId": "stream-task", "contextId": "stream-context",
                                          "artifact": {"artifactId": "stream-artifact", "parts": [{"text": str(index)}]},
                                          "append": True, "lastChunk": False}}
        chunks.append("data: " + json.dumps(payload, separators=(",", ":")) + "\n\n")
    return a2a.capture_sse_stream("".join(chunks).encode(), binding="HTTP+JSON",
                                  observed_at="2026-09-10T12:59:59Z")


def qualify(*, exchanges: int, agents: int, stream_events: int, out_dir: Path) -> dict:
    if not 2 <= exchanges <= MAX_EXCHANGES or exchanges % 2:
        raise ValueError("exchanges must be an even integer between 2 and 2000")
    if not 2 <= agents <= 32:
        raise ValueError("agents must be between 2 and 32")
    if not 2 <= stream_events <= 1000:
        raise ValueError("stream_events must be between 2 and 1000")
    out_dir.mkdir(parents=True, exist_ok=True)

    records = [_exchange(index, agents) for index in range(exchanges)]
    for record in records:
        a2a.validate_exchange(record)
    bundle = a2a.exchanges_to_aer(records, record_id="synthetic/a2a-v18-qualification")
    a2a.validate_aer_binding(bundle)
    stream = _stream(stream_events)

    sensitive_raw_retained = any(
        name in record["request_headers"]["safe_values"]
        for record in records for name in a2a.SENSITIVE_HEADERS
    )
    if sensitive_raw_retained:
        raise RuntimeError("sensitive request header leaked into safe_values")

    kinds: dict[str, int] = {}
    for node in bundle["aer"]["nodes"]:
        kinds[node["kind"]] = kinds.get(node["kind"], 0) + 1

    receipt = {
        "schema": SCHEMA,
        "profile": {"a2a_release": a2a.A2A_RELEASE, "bindings": sorted(a2a.SUPPORTED_BINDINGS)},
        "population": {"exchanges": exchanges, "agents": agents, "stream_events": stream_events},
        "observations": {
            "jsonrpc_exchanges": sum(record["binding"] == "JSONRPC" for record in records),
            "http_json_exchanges": sum(record["binding"] == "HTTP+JSON" for record in records),
            "version_1_0_matches": sum(record["service_parameters"]["version"]["matches_profile"] for record in records),
            "aer_nodes": len(bundle["aer"]["nodes"]),
            "aer_edges": len(bundle["aer"]["edges"]),
            "node_kinds": dict(sorted(kinds.items())),
            "sse_events": len(stream["events"]),
            "credential_header_values_retained": False,
        },
        "bindings": {
            "aer_record_sha256": bundle["aer"]["record_sha256"],
            "aer_bundle_sha256": bundle["bundle_sha256"],
            "stream_record_sha256": stream["record_sha256"],
            "exchange_set_sha256": aer.sha256_bytes(aer.canonical_bytes([r["record_sha256"] for r in records])),
        },
        "claims": {
            "synthetic_profile_qualified": True,
            "a2a_protocol_conformance_certified": False,
            "live_interoperability_verified": False,
            "grpc_binding_qualified": False,
            "agent_identity_verified": False,
            "request_authorization_verified": False,
            "task_history_complete": False,
            "production_scale_qualified": False,
            "private_reasoning_captured": False,
        },
    }
    receipt["receipt_sha256"] = aer.sha256_bytes(aer.canonical_bytes(receipt))
    (out_dir / "qualification-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sample-exchange.json").write_text(json.dumps(records[0], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "aer-summary.json").write_text(json.dumps({
        "record_sha256": bundle["aer"]["record_sha256"], "bundle_sha256": bundle["bundle_sha256"],
        "nodes": len(bundle["aer"]["nodes"]), "edges": len(bundle["aer"]["edges"]), "node_kinds": kinds,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exchanges", type=int, default=512)
    parser.add_argument("--agents", type=int, default=8)
    parser.add_argument("--stream-events", type=int, default=128)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    receipt = qualify(exchanges=args.exchanges, agents=args.agents,
                      stream_events=args.stream_events, out_dir=args.out_dir)
    print(json.dumps({"status": "PASS", "receipt_sha256": receipt["receipt_sha256"],
                      **receipt["population"], **receipt["observations"]}, sort_keys=True))


if __name__ == "__main__":
    main()
