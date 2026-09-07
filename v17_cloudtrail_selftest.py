"""Synthetic offline native CloudTrail import/replay acceptance."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_cloudtrail import TRANSFORMATION, TRANSFORMATION_VERSION, normalize
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture


def synthetic_event():
    return {
        "eventVersion": "1.11", "eventID": "synthetic-cloudtrail-event",
        "eventTime": TIMESTAMP, "eventSource": "bedrock.amazonaws.com",
        "eventName": "InvokeModel", "awsRegion": "us-east-1", "eventType": "AwsApiCall",
        "eventCategory": "Management", "requestID": "synthetic-request", "readOnly": False,
        "managementEvent": True, "recipientAccountId": "222222222222",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {
            "type": "AssumedRole", "principalId": "SYNTHETIC-ROLE:session",
            "arn": "arn:aws:sts::111111111111:assumed-role/SyntheticRole/session",
            "accountId": "111111111111", "accessKeyId": "synthetic-access-key-identifier",
            "sessionContext": {"sessionIssuer": {
                "type": "Role", "principalId": "SYNTHETIC-ROLE",
                "arn": "arn:aws:iam::111111111111:role/SyntheticRole", "accountId": "111111111111",
            }},
        },
        "requestParameters": {"modelId": "synthetic-model", "input": "SYNTHETIC-PROMPT-CONTENT"},
        "responseElements": None,
    }


def lookup_wrapper(event):
    return {"EventId": event["eventID"], "EventName": event["eventName"], "EventSource": event["eventSource"],
            "EventTime": event["eventTime"], "ReadOnly": str(event["readOnly"]).lower(),
            "CloudTrailEvent": json.dumps(event)}


def synthetic_cloudtrail_case(root: Path, input_format="records"):
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    events = [synthetic_event()]
    second = copy.deepcopy(events[0])
    second.update(eventID="synthetic-denied-event", eventName="InvokeAgent", errorCode="AccessDenied",
                  eventCategory="Data", managementEvent=False,
                  errorMessage="SYNTHETIC-ERROR-DETAIL", eventTime="2026-09-05T23:59:00Z")
    events.append(second)
    document = {"Records": events} if input_format == "records" else {"Events": [lookup_wrapper(e) for e in events], "NextToken": "synthetic-next-page"}
    raw = json.dumps(document, indent=2).encode("utf-8")
    private, public = root.parent / "cloudtrail-export.pem", root.parent / "cloudtrail-export.pub.pem"
    generate(private, public)
    return {"root": root, "raw": raw, "output": normalize(raw, input_format=input_format), "format": input_format,
            "private": private, "public": public, "package": root.parent / "cloudtrail-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"input_format": input_format}}


def export_fixture(fixture):
    profile = new_provenance(CASE_ID)
    for ident, name, raw in (
        ("CLOUDTRAIL-RAW", "cloudtrail-raw.json", fixture["raw"]),
        ("CLOUDTRAIL-NORMALIZED", "cloudtrail-normalized.json",
         fixture.get("output_bytes", canonical_json_bytes(fixture["output"]))),
    ):
        (fixture["root"] / name).write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id=ident, content=raw,
                                              acquired_at=TIMESTAMP, media_type="application/json")
        profile["artifacts"].append(wrap_record("artifacts", artifact, path=name))
    relation = EvidenceRelationship(
        case_id=CASE_ID, parent_artifact_id="CLOUDTRAIL-RAW", child_artifact_id="CLOUDTRAIL-NORMALIZED",
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
    with tempfile.TemporaryDirectory(prefix="ai-dfir-cloudtrail-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected CloudTrail replay network")):
            for input_format in ("records", "lookup-events"):
                fixture = synthetic_cloudtrail_case(Path(temporary) / input_format / "case", input_format)
                export_fixture(fixture)
                report = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                assert report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                fixture["output"]["events"][0]["event_name"] = "InventedEffect"
                export_fixture(fixture)
                report = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "native_formats": 2,
                      "incorrect_projection_detected": True, "source_authenticity_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
