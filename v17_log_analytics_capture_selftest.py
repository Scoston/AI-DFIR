"""Synthetic automatic acquisition-context capture and signed offline replay."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch

import requests

from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes
from v17_log_analytics_capture import TOKEN_ENV, capture
from v17_log_analytics_context_selftest import WORKSPACE, export_fixture, synthetic_context_case
from v17_log_analytics_selftest import synthetic_response

SYNTHETIC_TOKEN = "synthetic-capture-credential-not-a-live-token"


def synthetic_params():
    return {"workspace_id": WORKSPACE, "kql": "// SYNTHETIC-PRIVATE-CAPTURE-QUERY\nAzureActivity | summarize count()",
            "timespan": "PT12H", "workspaces": ["00000000-0000-0000-0000-000000000002"],
            "prefer": "wait=30", "client_request_id": "synthetic-client-request"}


class SyntheticStream(io.BytesIO):
    def read(self, size=-1, *, decode_content=False):
        assert 0 < size <= 64 * 1024 and decode_content is False
        return super().read(size)


def synthetic_adapter(raw, *, status=200, headers=None):
    class Adapter:
        sent = []
        closed = False
        response = None

        def __init__(self, *, max_retries):
            assert max_retries == 0

        def send(self, prepared, **kwargs):
            self.sent.append((prepared, kwargs))
            result = requests.Response()
            result.status_code, result.request, result.url = status, prepared, prepared.url
            result.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "application/json",
                "x-ms-request-id": "synthetic-ms-request", "request-id": "synthetic-other-request",
                "Content-Length": str(len(raw)), **(headers or {})})
            result.raw = SyntheticStream(raw)
            type(self).response = result
            return result

        def close(self):
            type(self).closed = True
    return Adapter


def captured_case(root, capture_dir):
    fixture = synthetic_context_case(root)
    fixture.update(raw=(capture_dir / "response.json").read_bytes(), context=(capture_dir / "context.json").read_bytes(),
                   output=json.loads((capture_dir / "projection.json").read_bytes()))
    export_fixture(fixture)
    return fixture


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-query-capture-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected network")):
            for partial in (False, True):
                raw = json.dumps(synthetic_response(partial=partial), indent=3).encode() + b"\n"
                adapter = synthetic_adapter(raw)
                directory = root / f"capture-{partial}"
                with patch.dict(os.environ, {TOKEN_ENV: SYNTHETIC_TOKEN}), patch.object(requests.adapters, "HTTPAdapter", adapter):
                    receipt = capture(canonical_json_bytes(synthetic_params()), directory)
                assert receipt["status"] == "CAPTURED" and receipt["artifact_set_complete"]
                assert receipt["collection_complete"] is (False if partial else None)
                assert (directory / "response.json").read_bytes() == raw
                assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed
                fixture = captured_case(root / f"case-{partial}", directory)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                ctx = json.loads(fixture["context"])
                ctx["request"]["body"]["query"] += " | take 1"
                fixture["context"] = canonical_json_bytes(ctx)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "synthetic_acquisition": True, "automatic_context": True,
                      "exact_response_bytes": True, "offline_replay": True, "substitution_detected": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
