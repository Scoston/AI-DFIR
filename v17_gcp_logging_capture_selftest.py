"""Synthetic one-page Google Cloud capture and signed offline replay acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch

import requests

from case_export_v17 import verify_case
from v17_gcp_audit_selftest import synthetic_entry
from v17_gcp_logging_capture import TOKEN_ENV, capture
from v17_gcp_logging_context import CONTEXT_SCHEMA, ENDPOINT, TRANSFORMATION, normalize
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter
from v17_log_analytics_context_selftest import export_fixture, synthetic_context_case


def synthetic_params():
    return {"resourceNames": ["projects/synthetic-source", "folders/123456"],
            "filter": 'logName:"cloudaudit.googleapis.com"\nseverity>=INFO',
            "orderBy": "timestamp desc", "pageSize": 1000, "pageToken": "SYNTHETIC-PRIVATE-PAGE"}


def synthetic_response(*, continuation=False, empty=False):
    return {"entries": [] if empty else [synthetic_entry()],
            **({"nextPageToken": "SYNTHETIC-PRIVATE-NEXT"} if continuation else {})}


def synthetic_context(raw):
    return {"schema": CONTEXT_SCHEMA,
            "request": {"method": "POST", "url": ENDPOINT, "body": synthetic_params(),
                        "headers": {"content-type": "application/json"}},
            "response": {"status": 200, "body_sha256": sha256_bytes(raw), "body_size_bytes": len(raw),
                         "headers": {"content-type": "application/json", "x-goog-request-id": "SYNTHETIC-REQUEST"}}}


def synthetic_logging_case(root, *, continuation=False, empty=False, capture_dir=None):
    fixture = synthetic_context_case(root)
    raw = json.dumps(synthetic_response(continuation=continuation, empty=empty), indent=3).encode() + b"\n"
    context = canonical_json_bytes(synthetic_context(raw))
    if capture_dir is not None:
        raw = (capture_dir / "response.json").read_bytes()
        context = (capture_dir / "context.json").read_bytes()
    output = normalize(raw, context_raw=context, input_format="entries-list")
    if capture_dir is not None:
        output = json.loads((capture_dir / "projection.json").read_bytes())
    fixture.update(raw=raw, context=context, output=output, transformation=TRANSFORMATION,
                   metadata={"input_format": "entries-list", "context_artifact_id": "QUERY-CONTEXT"})
    return fixture


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-gcp-logging-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected network")):
            for continuation in (False, True):
                for empty in (False, True):
                    raw = json.dumps(synthetic_response(continuation=continuation, empty=empty), indent=3).encode() + b"\n"
                    adapter = synthetic_adapter(raw, headers={"x-goog-request-id": "SYNTHETIC-REQUEST"})
                    folder = root / f"capture-{continuation}-{empty}"
                    with patch.dict(os.environ, {TOKEN_ENV: SYNTHETIC_TOKEN}), patch.object(requests.adapters, "HTTPAdapter", adapter):
                        receipt = capture(canonical_json_bytes(synthetic_params()), folder)
                    assert receipt["status"] == "CAPTURED" and receipt["artifact_set_complete"]
                    assert receipt["collection_complete"] is (False if continuation else None)
                    assert (folder / "response.json").read_bytes() == raw
                    assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed
                    fixture = synthetic_logging_case(root / f"case-{continuation}-{empty}", capture_dir=folder)
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                    context = json.loads(fixture["context"])
                    context["request"]["body"]["filter"] += " AND severity>=ERROR"
                    fixture["context"] = canonical_json_bytes(context)
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "synthetic_acquisition": True, "automatic_context": True,
                      "exact_response_bytes": True, "offline_replay": True, "substitution_detected": True,
                      "empty_page_continuation_preserved": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
