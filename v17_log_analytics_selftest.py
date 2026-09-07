"""Synthetic native Log Analytics import and signed-case replay acceptance."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_log_analytics import TRANSFORMATION, TRANSFORMATION_VERSION, normalize
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture


def synthetic_response(*, partial=False):
    columns = [
        {"name": "TimeGenerated", "type": "datetime"}, {"name": "Caller", "type": "string"},
        {"name": "count_", "type": "long"}, {"name": "RecordedFlag", "type": "bool"},
        {"name": "_BilledSize", "type": "real"}, {"name": "Properties_d", "type": "dynamic"},
        {"name": "Claims", "type": "string"}, {"name": "Claims_d", "type": "dynamic"},
        {"name": "SyntheticGuid", "type": "guid"}, {"name": "SyntheticInt", "type": "int"},
    ]
    row = ["2026-09-07T00:00:00.1234567Z", "synthetic-caller@example.invalid", 3, False, 123.5,
           {"request": "SYNTHETIC-PRIVATE-PAYLOAD"}, '{"oid":"SYNTHETIC-STRING-CLAIM"}',
           {"oid": "SYNTHETIC-DYNAMIC-CLAIM"}, "00000000-0000-0000-0000-000000000001", -2]
    earlier = copy.deepcopy(row)
    earlier[0], earlier[2] = "2026-09-06T23:59:00.123456789Z", 1
    result = {"tables": [
        {"name": "PrimaryResult", "columns": columns, "rows": [row, earlier]},
        {"name": "SyntheticSummary", "columns": [{"name": "count_", "type": "long"}], "rows": [[4]]},
    ], "statistics": {"query": {"details": "SYNTHETIC-QUERY-DETAIL"}}, "render": None}
    if partial:
        result["error"] = {"code": "PartialError", "message": "SYNTHETIC-PRIVATE-ERROR",
                           "details": [{"code": "PartialQueryFailure", "message": "SYNTHETIC-PRIVATE-DETAIL"}]}
    return result


def synthetic_query_case(root: Path, *, partial=False):
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    raw = json.dumps(synthetic_response(partial=partial), indent=2).encode()
    private, public = root.parent / "query-export.pem", root.parent / "query-export.pub.pem"
    generate(private, public)
    return {"root": root, "raw": raw, "output": normalize(raw, input_format="tables"),
            "private": private, "public": public, "package": root.parent / "query-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"input_format": "tables"}}


def export_fixture(fixture):
    profile = new_provenance(CASE_ID)
    for ident, name, raw in (
        ("QUERY-RAW", "query-raw.json", fixture["raw"]),
        ("QUERY-PROJECTION", "query-projection.json", fixture.get("output_bytes", canonical_json_bytes(fixture["output"]))),
    ):
        (fixture["root"] / name).write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id=ident, content=raw,
                                              acquired_at=TIMESTAMP, media_type="application/json")
        profile["artifacts"].append(wrap_record("artifacts", artifact, path=name))
    relation = EvidenceRelationship(
        case_id=CASE_ID, parent_artifact_id="QUERY-RAW", child_artifact_id="QUERY-PROJECTION",
        relationship_type="derived-from", transformation=fixture["transformation"],
        transformation_version=fixture["version"], created_at=TIMESTAMP, metadata=fixture["metadata"],
    )
    profile["relationships"].append(wrap_record("relationships", relation))
    ledger = bind_fixture(profile)
    signed, trust = sign_fixture(ledger)
    export_case(fixture["root"], TENANT_ID, CASE_ID, fixture["private"], fixture["package"],
                ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
    return fixture["package"]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-log-analytics-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected query replay network")):
            for partial in (False, True):
                fixture = synthetic_query_case(Path(temporary) / str(partial) / "case", partial=partial)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                replay = result["reconstruction"]["deterministic_replay"]
                assert result["valid"] and replay["status"] == "PASS"
                assert replay["transforms"][0]["partial_error_recorded"] is partial
                fixture["output"]["tables"][0]["rows"][0]["cells"][2]["value"] = 99
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "partial_error_preserved": True,
                      "incorrect_cell_projection_detected": True, "query_reexecuted": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
