#!/usr/bin/env python3
"""Synthetic signed-case acceptance for recorded Evidence Pack gate replay."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from evidence_pack_engine import assess
from fleet_crypto import generate
from v17_integrity import EvidenceArtifact, EvidenceRelationship, canonical_json_bytes, sha256_bytes
from v17_pack_replay import TRANSFORMATION, TRANSFORMATION_VERSION, prepare_replay_input
from v17_provenance import new_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture


def synthetic_pack_case(root: Path) -> dict:
    (root / "00_case").mkdir(parents=True)
    (root / "00_case/case.json").write_text(json.dumps({"case_id": CASE_ID, "tenant_id": TENANT_ID}), encoding="utf-8")
    raw = canonical_json_bytes({"event_id": "synthetic-event", "effect": "recorded-only"})
    (root / "source.json").write_bytes(raw)
    (root / "corroboration.json").write_bytes(raw)
    acquisition = {"artifacts": [{"relative_path": name, "sha256": sha256_bytes(raw)}
                                 for name in ("source.json", "corroboration.json")]}
    (root / "ACQUISITION_MANIFEST.json").write_bytes(canonical_json_bytes(acquisition))
    pack = {"schema": "ai-dfir/evidence-pack/v1.6", "id": "synthetic.recorded_gate", "title": "Synthetic recorded gate",
            "mandatory_min_quality": "VALIDATED", "artifacts": [
                {"id": ident, "title": ident, "priority": priority, "presence_patterns": [name],
                 "validation": {"format": "json", "require_acquisition_hash": True}}
                for ident, priority, name in (("source", "mandatory", "source.json"),
                    ("target", "mandatory", "target.json"), ("corroboration", "conditional", "corroboration.json"))],
            "conclusion_gates": [
                {"id": "source_qualified", "title": "Source meets recorded quality requirement", "requires": ["source"]},
                {"id": "impact_supported", "title": "Recorded ratings support impact", "requires": ["source", "target"],
                 "min_quality": "CORRELATED", "quality_requires": {"source": "VALIDATED"},
                 "allow_aliases": {"target": ["corroboration"]}}]}
    assessment = assess(pack, root)
    value = prepare_replay_input(pack, assessment, case_id=CASE_ID)
    private, public = root.parent / "pack-export.pem", root.parent / "pack-export.pub.pem"
    generate(private, public)
    return {"root": root, "pack": pack, "assessment": assessment, "input": value,
            "private": private, "public": public, "package": root.parent / "pack-case.zip",
            "transformation": TRANSFORMATION, "version": TRANSFORMATION_VERSION,
            "metadata": {"pack_sha256": value["pack_sha256"]}}


def export_fixture(fixture):
    root = fixture["root"]
    profile = new_provenance(CASE_ID)
    for ident, name, value in (("PACK-INPUT", "pack-replay-input.json", fixture["input"]),
                                ("PACK-ASSESSMENT", "pack-assessment.json", fixture["assessment"])):
        raw = canonical_json_bytes(value)
        if ident == "PACK-INPUT" and "input_bytes" in fixture:
            raw = fixture["input_bytes"]
        (root / name).write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id=ident, content=raw,
                                              acquired_at=TIMESTAMP, media_type="application/json")
        profile["artifacts"].append(wrap_record("artifacts", artifact, path=name))
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="PACK-INPUT", child_artifact_id="PACK-ASSESSMENT",
                                   relationship_type="derived-from", transformation=fixture["transformation"],
                                   transformation_version=fixture["version"], created_at=TIMESTAMP, metadata=fixture["metadata"])
    profile["relationships"].append(wrap_record("relationships", relation))
    ledger = bind_fixture(profile)
    signed, trust = sign_fixture(ledger)
    export_case(root, TENANT_ID, CASE_ID, fixture["private"], fixture["package"], ledger=ledger,
                signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
    fixture.update(profile=profile, ledger=ledger, signed=signed, trust=trust)
    return fixture["package"]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-pack-replay-") as temporary:
        fixture = synthetic_pack_case(Path(temporary) / "case")
        with patch.object(socket.socket, "connect", side_effect=AssertionError("replay attempted network")):
            export_fixture(fixture)
            report = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
            assert report["valid"] and report["provenance_integrity"] == "PASS"
            replay = report["reconstruction"]["deterministic_replay"]
            assert replay["status"] == "PASS"
            result = replay["transforms"][0]
            assert [gate["status"] for gate in result["gate_results"]] == ["supported", "not_supported"]
            assert result["recorded_quality_only"] and not result["raw_evidence_revalidated"]
            before = copy.deepcopy(fixture["assessment"])
            fixture["assessment"]["conclusion_gates"][1]["status"] = "supported"
            export_fixture(fixture)
            mismatched = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
            assert mismatched["valid"] and mismatched["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
            assert before["conclusion_gates"][1]["status"] == "not_supported"
    print(json.dumps({"status": "PASS", "offline": True, "recorded_gates_reproduced": True,
                      "incorrect_recorded_result_detected": True, "raw_quality_claims_revalidated": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
