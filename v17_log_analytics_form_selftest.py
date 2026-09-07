"""Synthetic explicit form GET acquisition and signed offline context replay."""
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
from v17_log_analytics_capture import TOKEN_ENV, _request, capture
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter
from v17_log_analytics_context import normalize
from v17_log_analytics_context_selftest import export_fixture
from v17_log_analytics_get_capture_selftest import synthetic_get_params
from v17_log_analytics_get_selftest import synthetic_get_case
from v17_log_analytics_resource_selftest import synthetic_resource_case, synthetic_resource_params


def synthetic_form_params(scope):
    params = synthetic_resource_params() if scope == "resource" else synthetic_get_params()
    params["kql"] = "print x=1+2, s='a b%20'"
    if scope == "workspace":
        params["workspaces"] = ["00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"]
    return params


def synthetic_form_case(root, *, scope="workspace", partial=False):
    fixture = (synthetic_resource_case(root, method="GET", partial=partial) if scope == "resource"
               else synthetic_get_case(root, partial=partial))
    ctx = json.loads(fixture["context"])
    ctx["request"] = _request(canonical_json_bytes(synthetic_form_params(scope)), method="GET", scope=scope, get_encoding="form")
    fixture["context"] = canonical_json_bytes(ctx)
    fixture["metadata"]["input_format"] = scope + "-get-form"
    fixture["output"] = normalize(fixture["raw"], context_raw=fixture["context"], input_format=fixture["metadata"]["input_format"])
    return fixture


def main():
    with tempfile.TemporaryDirectory(prefix="ai-dfir-get-form-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected live network")):
            for scope in ("workspace", "resource"):
                for partial in (False, True):
                    fixture = synthetic_form_case(root / f"{scope}-{partial}" / "case", scope=scope, partial=partial)
                    directory = fixture["root"].parent / "capture"
                    with patch.dict(os.environ, {TOKEN_ENV: SYNTHETIC_TOKEN}), patch.object(requests.adapters, "HTTPAdapter", synthetic_adapter(fixture["raw"])):
                        report = capture(canonical_json_bytes(synthetic_form_params(scope)), directory, method="GET", scope=scope, get_encoding="form")
                    assert report["status"] == "CAPTURED" and report["collection_complete"] is (False if partial else None)
                    fixture.update(context=(directory / "context.json").read_bytes(), output=json.loads((directory / "projection.json").read_bytes()))
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                    ctx = json.loads(fixture["context"])
                    ctx["request"]["url"] = ctx["request"]["url"].replace("%2B", "+")
                    fixture["context"] = canonical_json_bytes(ctx)
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "explicit_form_capture": True, "offline_replay": True,
                      "plus_space_substitution_detected": True, "effective_scope_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
