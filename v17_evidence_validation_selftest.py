"""Synthetic pinned raw-evidence assessment and signed replay acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_evidence_validation import RULES_SCHEMA, TRANSFORMATION, assess
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_context_selftest import export_fixture, synthetic_context_case
from v17_provenance_selftest import CASE_ID


def synthetic_rules(raw, *, fmt="json-array"):
    record_format = fmt not in ("text", "binary")
    return {"schema": RULES_SCHEMA, "case_id": CASE_ID, "format": fmt,
            "expected_sha256": sha256_bytes(raw), "min_size_bytes": 1, "max_size_bytes": 8 * 1024 * 1024,
            "require_records": record_format, "required_fields": ["id", "granted"] if record_format else [],
            "field_types": {"id": ["number", "string"], "granted": ["boolean"]} if record_format else {},
            "allow_extra_fields": not record_format, "required_text": []}


def synthetic_input(fmt="json-array", *, failing=False):
    record = b'{"id":9223372036854775807,"granted":' + (b'"false"' if failing else b'false') + b'}'
    return {"json-object": record, "json-array": b'[' + record + b']', "jsonl": record + b'\r\n',
            "text": b'SYNTHETIC-PRIVATE-TEXT', "binary": b'\xff\x00SYNTHETIC-BINARY'}[fmt]


def synthetic_validation_case(root, *, fmt="json-array", failing=False):
    fixture = synthetic_context_case(root)
    raw = synthetic_input(fmt, failing=failing); rules = synthetic_rules(raw, fmt=fmt)
    rules_raw = canonical_json_bytes(rules); pin = sha256_object(rules)
    fixture.update(raw=raw, context=rules_raw,
                   output=assess(raw, rules_raw=rules_raw, case_id=CASE_ID, expected_rules_sha256=pin),
                   transformation=TRANSFORMATION, metadata={"rules_artifact_id": "QUERY-CONTEXT", "rules_sha256": pin})
    return fixture


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-raw-assessment-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected assessment network")):
            for fmt in ("json-object", "json-array", "jsonl", "text", "binary"):
                fixture = synthetic_validation_case(Path(temporary) / fmt)
                assert fixture["output"]["validation_status"] == "SATISFIED"
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
            fixture = synthetic_validation_case(Path(temporary) / "failing", failing=True)
            assert fixture["output"]["validation_status"] == "NOT_SATISFIED"
            export_fixture(fixture)
            result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
            assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
            fixture["output"]["validation_status"] = "SATISFIED"
            export_fixture(fixture)
            result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
            assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "formats": 5, "raw_evidence_reassessed": True,
                      "reproduced_failed_validation": True, "incorrect_promotion_detected": True,
                      "network_required": False, "quality_rating_changed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
