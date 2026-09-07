"""Synthetic acceptance for separately bound query context and result replay."""
from __future__ import annotations

import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes, sha256_bytes
from v17_log_analytics_context import CONTEXT_SCHEMA, TRANSFORMATION, TRANSFORMATION_VERSION, normalize
from v17_log_analytics_selftest import synthetic_response
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture

WORKSPACE = "00000000-0000-0000-0000-000000000001"


def synthetic_context(raw):
    return {
        "schema": CONTEXT_SCHEMA,
        "request": {"method": "POST", "url": f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query",
                    "body": {"query": "// SYNTHETIC-PRIVATE-QUERY\nAzureActivity | summarize count()", "timespan": "PT12H",
                             "workspaces": ["00000000-0000-0000-0000-000000000002"]},
                    "headers": {"content-type": "application/json", "prefer": "wait=30"}},
        "response": {"status": 200, "body_sha256": sha256_bytes(raw), "body_size_bytes": len(raw),
                     "headers": {"x-ms-request-id": "SYNTHETIC-PRIVATE-REQUEST-ID"}},
    }


def synthetic_context_case(root: Path, *, partial=False):
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    raw = json.dumps(synthetic_response(partial=partial), indent=2).encode()
    context = canonical_json_bytes(synthetic_context(raw))
    private, public = root.parent / "context-export.pem", root.parent / "context-export.pub.pem"
    generate(private, public)
    return {"root": root, "raw": raw, "context": context,
            "output": normalize(raw, context_raw=context, input_format="workspace-post"),
            "private": private, "public": public, "package": root.parent / "context-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"input_format": "workspace-post", "context_artifact_id": "QUERY-CONTEXT"}}


def fixture_profile(fixture):
    profile = new_provenance(CASE_ID)
    for ident, name, raw in (
        ("QUERY-RAW", "query-raw.json", fixture["raw"]),
        ("QUERY-CONTEXT", "query-context.json", fixture["context"]),
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
    return profile


def export_fixture(fixture, *, profile=None):
    profile = fixture_profile(fixture) if profile is None else profile
    ledger = bind_fixture(profile)
    signed, trust = sign_fixture(ledger)
    export_case(fixture["root"], TENANT_ID, CASE_ID, fixture["private"], fixture["package"],
                ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
    return fixture["package"]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-query-context-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected context replay network")):
            for partial in (False, True):
                fixture = synthetic_context_case(Path(temporary) / str(partial) / "case", partial=partial)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
                assert result["valid"] and transform["status"] == "PASS" and transform["request_context_bound"]
                assert not transform["request_scope_verified"] and transform["partial_error_recorded"] is partial
                changed = json.loads(fixture["context"])
                changed["request"]["body"]["query"] += " | take 1"
                fixture["context"] = canonical_json_bytes(changed)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "context_substitution_detected": True,
                      "partial_error_preserved": True, "query_execution_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
