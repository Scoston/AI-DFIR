#!/usr/bin/env python3
"""Synthetic, offline acceptance case for investigation provenance and replay."""
from __future__ import annotations

import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from provider_normalizer import normalize
from v17_integrity import (
    AIProvenanceRecord, AnalystDecisionRecord, EvidenceArtifact, EvidenceRelationship,
    InvestigationLedger, sha256_object,
)
from v17_provenance import ToolActivityRecord, bind_record, new_provenance, wrap_record
from v17_signing import SignedLedgerCheckpoint

CASE_ID = "CASE-PROVENANCE-SYNTHETIC"
TENANT_ID = "TENANT-SYNTHETIC"
TIMESTAMP = "2026-09-06T00:00:00Z"


def synthetic_case(root: Path):
    """Small public test fixture; contains no real prompt, identity, or evidence."""
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(
        json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8",
    )
    rows = [{"id": "synthetic-request", "model": "synthetic-model", "timestamp": TIMESTAMP}]
    raw = json.dumps(rows).encode("utf-8")
    derived = json.dumps(normalize("openai", rows), indent=2).encode("utf-8")
    (root / "raw.json").write_bytes(raw)
    (root / "normalized.json").write_bytes(derived)
    bundle = new_provenance(CASE_ID)
    for ident, path, content in [("RAW", "raw.json", raw), ("NORMALIZED", "normalized.json", derived)]:
        artifact = EvidenceArtifact.from_bytes(
            case_id=CASE_ID, artifact_id=ident, content=content,
            acquired_at=TIMESTAMP, media_type="application/json", source_name="synthetic",
        )
        bundle["artifacts"].append(wrap_record("artifacts", artifact, path=path))
    relationship = EvidenceRelationship(
        case_id=CASE_ID, parent_artifact_id="RAW", child_artifact_id="NORMALIZED",
        relationship_type="normalized-from", transformation="provider_normalizer.normalize",
        transformation_version="1.4", created_at=TIMESTAMP,
        metadata={"provider": "openai"},
    )
    bundle["relationships"].append(wrap_record("relationships", relationship))
    ai = AIProvenanceRecord(
        case_id=CASE_ID, invocation_id="AI-001", provider="synthetic", model="synthetic-model",
        timestamp=TIMESTAMP, evidence_refs=("RAW",), retrieval_refs=("NORMALIZED",), tool_calls=("TOOL-001",),
    )
    bundle["ai_records"].append(wrap_record("ai_records", ai))
    tool = ToolActivityRecord(
        case_id=CASE_ID, activity_id="TOOL-001", invocation_id="AI-001", tool_name="synthetic.lookup",
        actor="synthetic-agent", timestamp=TIMESTAMP, status="succeeded",
        arguments_sha256=sha256_object({"synthetic": True}), evidence_refs=("RAW",), output_refs=("NORMALIZED",),
    )
    bundle["tool_records"].append(wrap_record("tool_records", tool))
    decision = AnalystDecisionRecord(
        case_id=CASE_ID, decision_id="DECISION-001", analyst_id="synthetic-analyst",
        target_id="AI-001", disposition="accepted_with_qualification", timestamp=TIMESTAMP,
        evidence_refs=("RAW", "NORMALIZED"),
    )
    bundle["analyst_decisions"].append(wrap_record("analyst_decisions", decision))
    return bundle, bind_fixture(bundle)


def bind_fixture(bundle):
    ledger = InvestigationLedger(CASE_ID)
    for kind in ("artifacts", "relationships", "ai_records", "tool_records", "analyst_decisions"):
        for row in bundle[kind]:
            rec = row["record"]
            bind_record(
                ledger, kind, row, timestamp=rec.get("timestamp") or TIMESTAMP,
                actor=rec.get("analyst_id") or rec.get("actor") or "synthetic-collector",
            )
    return ledger


def sign_fixture(ledger):
    key = Ed25519PrivateKey.generate()
    signed = SignedLedgerCheckpoint.sign(
        checkpoint=ledger.checkpoint(created_at=TIMESTAMP), private_key=key, signed_at=TIMESTAMP,
    )
    return signed, {signed.key_id: bytes.fromhex(signed.public_key_hex)}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-provenance-") as temporary:
        root = Path(temporary)
        profile, ledger = synthetic_case(root / "case")
        signed, trust = sign_fixture(ledger)
        private, public = root / "export.pem", root / "export.pub.pem"
        generate(private, public)
        package = root / "case.zip"
        with patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            export_case(root / "case", TENANT_ID, CASE_ID, private, package,
                        ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
            report = verify_case(package, public, require_provenance=True, include_reconstruction=True, replay_transforms=True)
        assert report["valid"], report
        assert report["provenance_integrity"] == "PASS"
        replay = report["reconstruction"]
        assert replay["record_count"] == 6
        assert replay["deterministic_replay"]["status"] == "PASS"
        assert replay["model_invoked"] is False and replay["tools_executed"] is False
        profile["ai_records"][0]["record"]["model"] = "changed-model"
        try:
            export_case(root / "case", TENANT_ID, CASE_ID, private, root / "bad.zip",
                        ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered provenance accepted")
    print(json.dumps({"status": "PASS", "records": 6, "offline": True, "tamper_rejected": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
