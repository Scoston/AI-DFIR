"""Synthetic nested shape drift and baseline-bound signed offline replay."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_integrity import sha256_bytes
from v17_log_analytics_context_selftest import export_fixture, synthetic_context_case
from v17_provenance_selftest import CASE_ID
from v17_schema_drift import TRANSFORMATION, compare


def synthetic_pair(fmt="json-array", *, changed=True):
    first = {"id": 9223372036854775807, "protoPayload": {
        "status": {"code": 0}, "authorizationInfo": [{"permission": "synthetic.read", "granted": True}]}}
    second = copy.deepcopy(first)
    second["protoPayload"]["authorizationInfo"][0]["permission"] = "synthetic.other"
    if changed:
        second["protoPayload"]["status"]["code"] = "0"
        second["protoPayload"]["authenticationInfo"] = {"principalSubject": "SYNTHETIC-PRIVATE-IDENTITY"}
    def encode(value):
        if fmt == "json-object": return json.dumps(value).encode()
        if fmt == "json-array": return json.dumps([value]).encode()
        if fmt == "jsonl": return json.dumps(value).encode() + b"\r\n"
        raise ValueError("unsupported synthetic format")
    return encode(first), encode(second)


def synthetic_drift_case(root, *, fmt="json-array", changed=True):
    fixture = synthetic_context_case(root)
    baseline, raw = synthetic_pair(fmt, changed=changed); pin = sha256_bytes(baseline)
    fixture.update(raw=raw, context=baseline,
                   output=compare(raw, baseline_raw=baseline, input_format=fmt, case_id=CASE_ID, expected_baseline_sha256=pin),
                   transformation=TRANSFORMATION,
                   metadata={"input_format": fmt, "baseline_artifact_id": "QUERY-CONTEXT", "baseline_sha256": pin})
    return fixture


def main():
    with tempfile.TemporaryDirectory(prefix="ai-dfir-nested-shape-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected structural replay network")):
            for fmt in ("json-object", "json-array", "jsonl"):
                for changed in (False, True):
                    fixture = synthetic_drift_case(Path(temporary) / f"{fmt}-{changed}", fmt=fmt, changed=changed)
                    assert fixture["output"]["observed_shape_changed"] is changed
                    assert fixture["output"]["bytes_changed"] and not fixture["output"]["provider_schema_change_proven"]
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
            fixture["output"]["provider_schema_change_proven"] = True
            export_fixture(fixture)
            result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
            assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "formats": 3, "nested_kind_change_detected": True,
                      "value_changes_do_not_imply_schema_changes": True, "incorrect_promotion_detected": True, "offline": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
