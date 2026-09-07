"""Synthetic Google Cloud Audit Log import and signed-case replay acceptance."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_gcp_audit import AUDIT_TYPE, TRANSFORMATION, TRANSFORMATION_VERSION, normalize
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture


def synthetic_entry():
    return {
        "logName": "projects/synthetic-source/logs/cloudaudit.googleapis.com%2Fdata_access",
        "resource": {"type": "audited_resource", "labels": {"project_id": "synthetic-source"}},
        "insertId": "synthetic-audit-entry", "timestamp": "2026-09-07T00:00:00.123456789Z",
        "receiveTimestamp": "2026-09-07T00:00:01.000000001Z", "severity": "INFO",
        "protoPayload": {
            "@type": AUDIT_TYPE, "serviceName": "aiplatform.googleapis.com",
            "methodName": "google.cloud.aiplatform.v1.PredictionService.Predict",
            "resourceName": "projects/synthetic-target/locations/us-central1/endpoints/synthetic",
            "authenticationInfo": {
                "principalEmail": "synthetic-agent@synthetic-project.iam.gserviceaccount.com",
                "principalSubject": "serviceAccount:synthetic-agent@synthetic-project.iam.gserviceaccount.com",
                "authoritySelector": "synthetic-selector",
                "serviceAccountKeyName": "SYNTHETIC-KEY-IDENTIFIER",
                "serviceAccountDelegationInfo": [
                    {"firstPartyPrincipal": {"principalEmail": "synthetic-operator@example.invalid",
                                             "serviceMetadata": {"context": "SYNTHETIC-SERVICE-DETAIL"}}},
                    {"principalSubject": "principal://iam.googleapis.com/synthetic-pool/subject/synthetic-workload",
                     "thirdPartyPrincipal": {"thirdPartyClaims": {"sub": "SYNTHETIC-PRIVATE-CLAIM"}}},
                ],
            },
            "authorizationInfo": [
                {"resource": "projects/synthetic-target/endpoints/synthetic", "permission": "aiplatform.endpoints.predict", "granted": True},
                {"resource": "projects/synthetic-target/buckets/synthetic", "permission": "storage.objects.get", "granted": False},
            ],
            "requestMetadata": {"callerIp": "192.0.2.20", "requestAttributes": {"reason": "SYNTHETIC-REQUEST-DETAIL"}},
            "status": {"code": 7, "message": "SYNTHETIC-ERROR-CONTENT"},
            "request": {"instances": ["SYNTHETIC-PROMPT-CONTENT"]}, "response": None,
        },
        "operation": {"id": "synthetic-operation", "producer": "synthetic-producer", "first": True, "last": False},
    }


def synthetic_audit_case(root: Path, input_format="entries"):
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    entries = [synthetic_entry()]
    second = copy.deepcopy(entries[0])
    second.update(insertId="synthetic-earlier-entry", timestamp="2026-09-06T23:59:00.987654321Z")
    second["protoPayload"]["status"] = {}
    entries.append(second)
    document = {"entries": entries, "nextPageToken": "synthetic-continuation"} if input_format == "entries" else entries
    raw = json.dumps(document, indent=2).encode()
    private, public = root.parent / "audit-export.pem", root.parent / "audit-export.pub.pem"
    generate(private, public)
    return {"root": root, "raw": raw, "output": normalize(raw, input_format=input_format), "format": input_format,
            "private": private, "public": public, "package": root.parent / "audit-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"input_format": input_format}}


def export_fixture(fixture):
    profile = new_provenance(CASE_ID)
    for ident, name, raw in (
        ("AUDIT-RAW", "audit-raw.json", fixture["raw"]),
        ("AUDIT-PROJECTION", "audit-projection.json", fixture.get("output_bytes", canonical_json_bytes(fixture["output"]))),
    ):
        (fixture["root"] / name).write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id=ident, content=raw,
                                              acquired_at=TIMESTAMP, media_type="application/json")
        profile["artifacts"].append(wrap_record("artifacts", artifact, path=name))
    relation = EvidenceRelationship(
        case_id=CASE_ID, parent_artifact_id="AUDIT-RAW", child_artifact_id="AUDIT-PROJECTION",
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
    with tempfile.TemporaryDirectory(prefix="ai-dfir-gcp-audit-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected audit replay network")):
            for input_format in ("entries", "array"):
                fixture = synthetic_audit_case(Path(temporary) / input_format / "case", input_format)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                fixture["output"]["entries"][0]["authorizations"][1]["granted"] = True
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "native_formats": 2,
                      "incorrect_authorization_projection_detected": True, "source_authenticity_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

