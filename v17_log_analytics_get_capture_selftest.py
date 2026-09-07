"""Synthetic workspace GET capture with automatic signed-case replay inputs."""
from __future__ import annotations

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
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter, synthetic_params
from v17_log_analytics_context_selftest import export_fixture
from v17_log_analytics_get_selftest import synthetic_get_case
from v17_log_analytics_selftest import synthetic_response


def synthetic_get_params():
    params = synthetic_params()
    del params["workspaces"]
    return params


def captured_get_case(root, capture_dir):
    fixture = synthetic_get_case(root)
    fixture.update(raw=(capture_dir / "response.json").read_bytes(), context=(capture_dir / "context.json").read_bytes(),
                   output=json.loads((capture_dir / "projection.json").read_bytes()))
    export_fixture(fixture)
    return fixture


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-get-capture-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected live network")):
            for partial in (False, True):
                raw = json.dumps(synthetic_response(partial=partial), indent=3).encode() + b"\n"
                adapter = synthetic_adapter(raw)
                directory = root / f"capture-{partial}"
                with patch.dict(os.environ, {TOKEN_ENV: SYNTHETIC_TOKEN}), patch.object(requests.adapters, "HTTPAdapter", adapter):
                    receipt = capture(canonical_json_bytes(synthetic_get_params()), directory, method="GET")
                assert receipt["status"] == "CAPTURED" and receipt["input_format"] == "workspace-get"
                assert receipt["collection_complete"] is (False if partial else None)
                assert (directory / "response.json").read_bytes() == raw
                assert len(adapter.sent) == 1 and adapter.sent[0][0].method == "GET" and adapter.sent[0][0].body is None
                assert adapter.closed and adapter.response.raw.closed
                fixture = captured_get_case(root / f"case-{partial}", directory)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                changed = json.loads(fixture["context"])
                changed["request"]["url"] += "%20"
                fixture["context"] = canonical_json_bytes(changed)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "synthetic_get_acquisition": True, "automatic_context": True,
                      "exact_response_bytes": True, "offline_replay": True, "substitution_detected": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
