"""Synthetic resource-scoped capture, permission binding, and signed replay."""
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
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter
from v17_log_analytics_context import normalize
from v17_log_analytics_context_selftest import export_fixture, synthetic_context, synthetic_context_case
from v17_log_analytics_selftest import synthetic_response

RESOURCE_ID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/synthetic-rg/providers/Microsoft.Compute/virtualMachines/synthetic-vm"


def synthetic_resource_response(*, partial=False):
    response = synthetic_response(partial=partial)
    response["permissions"] = {"resources": [{"resourceId": RESOURCE_ID, "denyTables": ["SyntheticDenied"]}]}
    return response


def synthetic_resource_params():
    return {"resource_id": RESOURCE_ID, "kql": "AzureActivity | count", "timespan": "PT1H",
            "prefer": "include-permissions=true"}


def synthetic_resource_case(root, *, method="POST", partial=False):
    from v17_log_analytics_capture import _request
    fixture = synthetic_context_case(root, partial=partial)
    raw = json.dumps(synthetic_resource_response(partial=partial), indent=2).encode()
    ctx = synthetic_context(raw)
    ctx["request"] = _request(canonical_json_bytes(synthetic_resource_params()), method=method, scope="resource")
    fixture.update(raw=raw, context=canonical_json_bytes(ctx))
    fixture["metadata"]["input_format"] = "resource-" + method.lower()
    fixture["output"] = normalize(raw, context_raw=fixture["context"], input_format=fixture["metadata"]["input_format"])
    return fixture


def main():
    with tempfile.TemporaryDirectory(prefix="ai-dfir-resource-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected live network")):
            for method in ("POST", "GET"):
                for partial in (False, True):
                    fixture = synthetic_resource_case(root / f"{method}-{partial}" / "case", method=method, partial=partial)
                    directory = fixture["root"].parent / "capture"
                    adapter = synthetic_adapter(fixture["raw"])
                    with patch.dict(os.environ, {TOKEN_ENV: SYNTHETIC_TOKEN}), patch.object(requests.adapters, "HTTPAdapter", adapter):
                        report = capture(canonical_json_bytes(synthetic_resource_params()), directory, method=method, scope="resource")
                    assert report["status"] == "CAPTURED" and report["collection_complete"] is (False if partial else None)
                    fixture.update(context=(directory / "context.json").read_bytes(),
                                   output=json.loads((directory / "projection.json").read_bytes()))
                    export_fixture(fixture)
                    verified = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                    assert verified["valid"] and verified["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                    ctx = json.loads(fixture["context"])
                    ctx["request"]["url"] = ctx["request"]["url"].replace("synthetic-vm", "another-vm")
                    fixture["context"] = canonical_json_bytes(ctx)
                    export_fixture(fixture)
                    verified = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                    assert verified["valid"] and verified["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "synthetic_resource_capture": True, "offline_replay": True,
                      "resource_substitution_detected": True, "permissions_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
