"""Synthetic Azure Activity Log import and signed-case replay acceptance."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_azure_activity import TRANSFORMATION, TRANSFORMATION_VERSION, normalize
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture


def synthetic_event():
    return {
        "eventDataId": "synthetic-event", "eventTimestamp": "2026-09-07T00:00:00.9792776Z",
        "submissionTimestamp": "2026-09-07T00:00:01.9936304Z",
        "id": "/subscriptions/synthetic-source/events/synthetic-event",
        "caller": "synthetic-app", "level": "Informational",
        "operationId": "synthetic-operation", "correlationId": "synthetic-correlation",
        "resourceId": "/subscriptions/synthetic-target/resourceGroups/synthetic-group/providers/Microsoft.CognitiveServices/accounts/synthetic-account",
        "resourceGroupName": "synthetic-group", "subscriptionId": "synthetic-target", "tenantId": "synthetic-event-tenant",
        "operationName": {"value": "Microsoft.CognitiveServices/accounts/write", "localizedValue": "Créer ou modifier un compte"},
        "eventName": {"value": "EndRequest", "localizedValue": "Fin de la demande"},
        "category": {"value": "Administrative", "localizedValue": "Administratif"},
        "resourceProviderName": {"value": "Microsoft.CognitiveServices", "localizedValue": "Services cognitifs"},
        "resourceType": {"value": "Microsoft.CognitiveServices/accounts", "localizedValue": "Comptes"},
        "status": {"value": "Succeeded", "localizedValue": "Réussi"},
        "subStatus": {"value": "Created", "localizedValue": "Créé (HTTP 201)"},
        "authorization": {"action": "Microsoft.CognitiveServices/accounts/write", "role": "Contributor",
                          "scope": "/subscriptions/synthetic-target", "privateDetail": "SYNTHETIC-AUTHORIZATION-DETAIL"},
        "claims": {
            "appid": "synthetic-app", "oid": "synthetic-short-object", "tid": "synthetic-short-tenant", "idtyp": "app",
            "http://schemas.microsoft.com/identity/claims/objectidentifier": "synthetic-long-object",
            "http://schemas.microsoft.com/identity/claims/tenantid": "synthetic-long-tenant",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "synthetic-name-claim",
            "privateClaim": "SYNTHETIC-PRIVATE-CLAIM",
        },
        "httpRequest": {"clientRequestId": "synthetic-request", "clientIpAddress": "192.0.2.20", "method": "PUT",
                        "uri": "https://management.example.invalid/synthetic?sig=SYNTHETIC-URI-SECRET"},
        "properties": {"responseBody": "SYNTHETIC-RESPONSE-CONTENT"}, "description": "SYNTHETIC-DESCRIPTION-CONTENT",
    }


def synthetic_activity_case(root: Path, input_format="activity-log"):
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    events = [synthetic_event()]
    second = copy.deepcopy(events[0])
    second.update(eventDataId="synthetic-earlier-event", eventTimestamp="2026-09-06T23:59:00.9876543Z")
    second["status"] = {"value": "Started"}
    events.append(second)
    document = {"value": events, "nextLink": "https://management.example.invalid/?skiptoken=synthetic-next"} if input_format == "activity-log" else events
    raw = json.dumps(document, indent=2).encode()
    private, public = root.parent / "activity-export.pem", root.parent / "activity-export.pub.pem"
    generate(private, public)
    return {"root": root, "raw": raw, "output": normalize(raw, input_format=input_format), "format": input_format,
            "private": private, "public": public, "package": root.parent / "activity-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"input_format": input_format}}


def export_fixture(fixture):
    profile = new_provenance(CASE_ID)
    for ident, name, raw in (
        ("ACTIVITY-RAW", "activity-raw.json", fixture["raw"]),
        ("ACTIVITY-PROJECTION", "activity-projection.json", fixture.get("output_bytes", canonical_json_bytes(fixture["output"]))),
    ):
        (fixture["root"] / name).write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id=ident, content=raw,
                                              acquired_at=TIMESTAMP, media_type="application/json")
        profile["artifacts"].append(wrap_record("artifacts", artifact, path=name))
    relation = EvidenceRelationship(
        case_id=CASE_ID, parent_artifact_id="ACTIVITY-RAW", child_artifact_id="ACTIVITY-PROJECTION",
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
    with tempfile.TemporaryDirectory(prefix="ai-dfir-azure-activity-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected activity replay network")):
            for input_format in ("activity-log", "array"):
                fixture = synthetic_activity_case(Path(temporary) / input_format / "case", input_format)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                fixture["output"]["events"][0]["actor"]["claims"]["oid"] = "incorrectly-coalesced-object"
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "native_formats": 2,
                      "incorrect_identity_projection_detected": True, "source_authenticity_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
