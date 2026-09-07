from __future__ import annotations

import copy
import io
import json
import os
import socket
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

import pytest

import case_exchange_v17 as cli
import case_export_v17 as verifier
import v17_case_exchange as exchange
from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_integrity import EvidenceArtifact, canonical_json_bytes, sha256_bytes, sha256_object
from v17_key_policy_selftest import EVALUATED_AT, synthetic_export
from v17_provenance import PROVENANCE_PATH, ProvenanceError, record_hash, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, bind_fixture, sign_fixture, synthetic_case

OPTIONS = {"expected_tenant": TENANT_ID, "expected_case": CASE_ID}


@pytest.fixture
def case(tmp_path):
    value = synthetic_export(tmp_path)
    value["raw"] = value["package"].read_bytes()
    return value


def graph(case, **options):
    return exchange.export_exchange(case["raw"], case["public"], **{**OPTIONS, **options})


def nodes(value, node_type):
    return [n for n in value["@graph"] if n["@type"] == node_type]


def investigation(value):
    return nodes(value, "case-investigation:Investigation")[0]


def compare(case, value, **options):
    return exchange.compare_exchange(case["raw"], json.dumps(value).encode(), case["public"], **{**OPTIONS, **options})


def altered_archive(raw, member, data):
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(target, "w") as out:
        for info in source.infolist():
            out.writestr(info, data if info.filename == member else source.read(info))
    return target.getvalue()


def custom_case(root, amend):
    profile, _ = synthetic_case(root / "case")
    amend(profile, root / "case")
    for kind in ("artifacts", "relationships", "ai_records", "tool_records", "analyst_decisions"):
        for row in profile[kind]:
            row["record_hash"] = record_hash(row)
    ledger = bind_fixture(profile)
    signed, trust = sign_fixture(ledger)
    private, public, path = root / "key.pem", root / "key.pub.pem", root / "custom.zip"
    generate(private, public)
    export_case(root / "case", TENANT_ID, CASE_ID, private, path, ledger=ledger,
                signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
    return {"raw": path.read_bytes(), "public": public}


def test_inventory_hashes_sizes_and_references_come_from_verified_bytes(case):
    value = graph(case)
    by_id = {n["@id"]: n for n in value["@graph"]}
    assert len(by_id) == len(value["@graph"]) == 11
    assert list(by_id) == sorted(by_id)
    for ident in by_id:
        assert uuid.UUID(ident.removeprefix("urn:uuid:")).version == 5
    with zipfile.ZipFile(io.BytesIO(case["raw"])) as archive:
        for obj in nodes(value, "uco-observable:ObservableObject"):
            raw = archive.read(obj["adfir:packagePath"]) if "adfir:packagePath" in obj else case["raw"]
            facet = by_id[obj["uco-core:hasFacet"][0]["@id"]]
            digest = by_id[facet["uco-observable:hash"][0]["@id"]]
            assert facet["uco-observable:sizeInBytes"] == len(raw)
            assert digest["uco-types:hashValue"] == {"@type": "xsd:hexBinary", "@value": sha256_bytes(raw)}
    case_node = investigation(value)
    assert len(case_node["uco-core:object"]) == 4
    assert all(ref["@id"] in by_id for ref in case_node["uco-core:object"])
    assert case_node["adfir:recordCount"] == 6 and case_node["adfir:omittedRecordCount"] == 3
    assert case_node["adfir:artifactCount"] == 2 and case_node["adfir:relationshipCount"] == 1
    assert "MODEL_INVOKED" not in json.dumps(value) and "synthetic-agent" not in json.dumps(value)


def test_recorded_relationship_direction_and_commitments_are_preserved(case):
    value = graph(case)
    relation = nodes(value, "uco-core:Relationship")[0]
    artifacts = {n["adfir:artifactID"]: n for n in value["@graph"] if "adfir:artifactID" in n}
    assert relation["uco-core:source"] == [{"@id": artifacts["NORMALIZED"]["@id"]}]
    assert relation["uco-core:target"] == {"@id": artifacts["RAW"]["@id"]}
    assert relation["uco-core:isDirectional"] is True and relation["adfir:executionVerified"] is False
    source = case["profile"]["relationships"][0]
    assert relation["adfir:recordHash"] == source["record_hash"]
    assert relation["adfir:recordedRelationshipType"] == "normalized-from"
    assert relation["adfir:recordedTransformation"] == "provider_normalizer.normalize"
    assert relation["adfir:recordedMetadataHash"] == sha256_object(source["record"]["metadata"])


@pytest.mark.parametrize("transformation,field,predicate,metadata", [
    ("v17_log_analytics_context.normalize", "context_artifact_id", "adfir:contextArtifact", {"input_format": "workspace-post"}),
    ("v17_gcp_logging_context.normalize", "context_artifact_id", "adfir:contextArtifact", {"input_format": "entries-list"}),
    ("v17_evidence_validation.assess", "rules_artifact_id", "adfir:rulesArtifact", {"rules_sha256": "1" * 64}),
    ("v17_schema_drift.compare", "baseline_artifact_id", "adfir:baselineArtifact", {"input_format": "json-object", "baseline_sha256": "1" * 64}),
])
def test_additional_verified_lineage_references_are_retained(tmp_path, transformation, field, predicate, metadata):
    def amend(profile, root):
        raw = b'{"synthetic":"additional input"}'
        (root / "additional.json").write_bytes(raw)
        artifact = EvidenceArtifact.from_bytes(case_id=CASE_ID, artifact_id="ADDITIONAL", content=raw)
        profile["artifacts"].append(wrap_record("artifacts", artifact, path="additional.json"))
        profile["relationships"][0]["record"].update(transformation=transformation,
            transformation_version="1.7", metadata={**metadata, field: "ADDITIONAL"})
    value = graph(custom_case(tmp_path, amend))
    target = next(n for n in value["@graph"] if n.get("adfir:artifactID") == "ADDITIONAL")
    assert nodes(value, "uco-core:Relationship")[0][predicate] == {"@id": target["@id"]}
    # The view records bound relationships; it does not run those transforms.
    assert investigation(value)["adfir:executionVerified"] is False


@pytest.mark.parametrize("flag", ["sourceAuthenticityVerified", "executionVerified", "completeInvestigationExport",
    "qualityRatingChanged", "closureAuthorized", "networkRequired", "graphSignaturePresent", "runtimeSHACLValidationPerformed"])
def test_no_authority_execution_or_completeness_promotion(case, flag):
    assert investigation(graph(case))["adfir:" + flag] is False


def test_verifier_report_is_bound_without_embedding_content(case):
    value = graph(case)
    report = verify_case(case["raw"], case["public"], **OPTIONS,
                         require_provenance=True, include_reconstruction=True,
                         max_members=exchange.MAX_MEMBERS, max_total_uncompressed=exchange.MAX_TOTAL_UNCOMPRESSED,
                         max_member_uncompressed=exchange.MAX_MEMBER_BYTES)
    assert investigation(value)["adfir:verificationReportHash"] == sha256_object(report)
    assert investigation(value)["adfir:checkpointHash"] == report["checkpoint_hash"]
    assert investigation(value)["adfir:checkpointKeyPolicyStatus"] == "NOT_CONFIGURED"
    assert investigation(value)["adfir:collectionCompleteness"] == "unknown"


def test_repeatable_graph_and_formatting_only_comparison(case):
    first = graph(case)
    assert graph(case) == first
    assert compare(case, first)["status"] == "PASS"
    pretty = json.dumps(first, indent=2, sort_keys=True).encode()
    assert exchange.compare_exchange(case["raw"], pretty, case["public"], **OPTIONS)["status"] == "PASS"


@pytest.mark.parametrize("kind,identity", [("archive", "source"), ("artifact", "a:b"), ("artifact:a", "b"), ("artifact", "é")])
def test_instance_ids_are_independently_reproducible_and_archive_scoped(kind, identity):
    digest = "1" * 64
    name = canonical_json_bytes([exchange.PROFILE, digest, kind, identity]).decode()
    expected = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, name))
    assert exchange._node_id(digest, kind, identity) == expected
    assert exchange._node_id("2" * 64, kind, identity) != expected


@pytest.mark.parametrize("mutation", [
    lambda g: g.update({"@context": "https://example.invalid/context.jsonld"}),
    lambda g: g["@context"].update({"uco-types": "https://example.invalid/"}),
    lambda g: g["@graph"].reverse(),
    lambda g: g["@graph"].pop(),
    lambda g: g["@graph"].append(copy.deepcopy(g["@graph"][0])),
    lambda g: investigation(g).update({"adfir:sourceAuthenticityVerified": True}),
    lambda g: investigation(g).update({"adfir:closureAuthorized": True}),
    lambda g: investigation(g).update({"adfir:omittedRecordCount": 0}),
    lambda g: investigation(g).update({"adfir:tenantID": "OTHER"}),
    lambda g: investigation(g).update({"adfir:verificationReportHash": "0" * 64}),
    lambda g: nodes(g, "uco-core:Relationship")[0].pop("uco-core:target"),
    lambda g: nodes(g, "uco-core:Relationship")[0].update({"adfir:recordedTransformation": "untrusted.execute"}),
    lambda g: nodes(g, "uco-types:Hash")[0]["uco-types:hashValue"].update({"@value": "0" * 64}),
    lambda g: nodes(g, "uco-types:Hash")[0]["uco-types:hashValue"].update({"@type": "xsd:string"}),
    lambda g: nodes(g, "uco-observable:ContentDataFacet")[0].update({"uco-observable:sizeInBytes": 0}),
])
def test_complete_comparison_rejects_graph_and_claim_substitution_without_network(case, monkeypatch, mutation):
    value = graph(case); mutation(value)
    def blocked(*a, **kw): raise AssertionError("network attempted")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    assert compare(case, value)["status"] == "FAIL"


@pytest.mark.parametrize("number", [2.0, "2", True, None])
def test_integer_types_cannot_be_substituted_even_when_jcs_normalizes_float(case, number):
    value = graph(case); investigation(value)["adfir:artifactCount"] = number
    assert compare(case, value)["status"] == "FAIL"


@pytest.mark.parametrize("member", ["raw.json", PROVENANCE_PATH, verifier.LEDGER_PATH,
    verifier.CHECKPOINT_PATH, verifier.SIGNED_CHECKPOINT_PATH, verifier.TRUST_STORE_PATH, verifier.V15_MANIFEST_PATH])
def test_any_modified_signed_member_blocks_export(case, member):
    raw = altered_archive(case["raw"], member, b'{"changed":true}')
    with pytest.raises(ProvenanceError):
        exchange.export_exchange(raw, case["public"], **OPTIONS)


def test_wrong_external_manifest_key_blocks_export(case, tmp_path):
    generate(tmp_path / "other.pem", tmp_path / "other.pub.pem")
    with pytest.raises(ProvenanceError):
        exchange.export_exchange(case["raw"], tmp_path / "other.pub.pem", **OPTIONS)


@pytest.mark.parametrize("option,value", [("expected_case", "OTHER"), ("expected_tenant", "OTHER"),
    ("expected_case", ""), ("expected_tenant", None), ("expected_case", "a\n"), ("expected_tenant", "a" * 4097)])
def test_explicit_identity_is_mandatory(case, option, value):
    with pytest.raises(ProvenanceError): graph(case, **{option: value})


@pytest.mark.parametrize("option", ["require_provenance", "include_reconstruction", "replay_transforms",
    "max_members", "max_total_uncompressed", "max_member_uncompressed", "max_compression_ratio", "url"])
def test_callers_cannot_disable_gates_or_select_transforms(case, option):
    with pytest.raises(ProvenanceError): graph(case, **{option: False})


@pytest.mark.parametrize("option", ["require_checkpoint_key_policy", "require_checkpoint_timestamp", "require_key_trust_history",
    "require_authenticated_key_policy"])
def test_required_independent_gates_are_enforced(case, option):
    with pytest.raises(ProvenanceError): graph(case, **{option: True})


def test_valid_policy_pin_is_bound_and_revoked_key_is_rejected(case):
    options = {"checkpoint_key_policy": case["policy"], "key_policy_evaluated_at": EVALUATED_AT,
               "expected_key_policy_sha256": sha256_object(case["policy"]), "require_checkpoint_key_policy": True}
    value = graph(case, **options)
    assert investigation(value)["adfir:checkpointKeyPolicyStatus"] == "PASS"
    assert compare(case, value, **options)["status"] == "PASS"
    assert compare(case, value)["status"] == "FAIL"
    with pytest.raises(ProvenanceError): graph(case, **{**options, "expected_key_policy_sha256": "0" * 64})
    revoked = copy.deepcopy(case["policy"])
    revoked["keys"][0].update(state="revoked", status_changed_at="2026-09-06T00:00:30Z", reason="synthetic")
    with pytest.raises(ProvenanceError):
        graph(case, **{**options, "checkpoint_key_policy": revoked, "expected_key_policy_sha256": sha256_object(revoked)})


def test_immutable_snapshot_is_used_for_hash_verification_and_projection(case, monkeypatch):
    captured = case["raw"]
    original = exchange.verify_case
    def verify(raw, key, **options):
        assert raw is captured and isinstance(raw, bytes)
        case["package"].write_bytes(b"replaced outside snapshot")
        return original(raw, key, **options)
    monkeypatch.setattr(exchange, "verify_case", verify)
    monkeypatch.setattr(verifier, "_sha256_file", lambda *args: pytest.fail("reopened a path to hash"))
    assert investigation(graph(case))["adfir:sourceCaseIntegrityVerified"]
    assert case["package"].read_bytes() == b"replaced outside snapshot"


def test_bytes_verification_matches_existing_path_api(case):
    options = {**OPTIONS, "require_provenance": True, "include_reconstruction": True}
    assert verify_case(case["raw"], case["public"], **options) == verify_case(case["package"], case["public"], **options)


@pytest.mark.parametrize("raw", [b"", b"not a zip", bytearray(b"zip"), memoryview(b"zip"), None])
def test_invalid_or_mutable_archive_inputs_fail(case, raw):
    with pytest.raises(ProvenanceError): exchange.export_exchange(raw, case["public"], **OPTIONS)


@pytest.mark.parametrize("limit", ["MAX_ARCHIVE_BYTES", "MAX_TOTAL_UNCOMPRESSED", "MAX_MEMBER_BYTES", "MAX_MEMBERS", "MAX_OUTPUT_BYTES", "MAX_GRAPH_NODES"])
def test_resource_limits_cannot_return_partial_success(case, monkeypatch, limit):
    monkeypatch.setattr(exchange, limit, 1)
    with pytest.raises(ProvenanceError): graph(case)


def test_output_has_to_fit_comparison_tree_budget(case, monkeypatch):
    import v17_log_analytics
    monkeypatch.setattr(v17_log_analytics, "MAX_NODES", 10)
    with pytest.raises(ProvenanceError): graph(case)


def test_identifier_collision_fails_closed(case, monkeypatch):
    monkeypatch.setattr(exchange, "_node_id", lambda *args: "urn:uuid:" + str(uuid.UUID(int=0)))
    with pytest.raises(ProvenanceError, match="collision"): graph(case)


@pytest.mark.parametrize("raw", [b"", b"{", b'{"@graph":[],"@graph":[]}', b'"\xff"', b'{"x":NaN}',
    b'{"x":Infinity}', b'{"x":1e999}', b'{"x":"\\ud800"}', b'[' * 34 + b'0' + b']' * 34])
def test_invalid_or_excessive_comparison_json_fails(case, raw):
    with pytest.raises((ValueError, UnicodeError)):
        exchange.compare_exchange(case["raw"], raw, case["public"], **OPTIONS)


def test_recorded_labels_and_jsonld_keywords_are_literals(tmp_path):
    def amend(profile, root):
        profile["artifacts"][0]["record"].update(classification="@context: https://example.invalid/秘密",
            media_type="@id: urn:example:literal", source_name="DO-NOT-EXPORT-SOURCE")
        profile["artifacts"][0]["record"]["metadata"] = {"private-note": "DO-NOT-EXPORT-METADATA"}
    value = graph(custom_case(tmp_path, amend))
    raw = next(n for n in value["@graph"] if n.get("adfir:artifactID") == "RAW")
    assert isinstance(raw["adfir:recordedClassification"], str)
    assert raw["adfir:recordedMediaType"] == "@id: urn:example:literal"
    assert "DO-NOT-EXPORT" not in json.dumps(value) and value["@context"] == exchange.CONTEXT


def test_unknown_transform_version_is_preserved_without_interpreting_its_metadata(tmp_path):
    def amend(profile, root):
        profile["relationships"][0]["record"].update(transformation="v17_schema_drift.compare",
            transformation_version="999", metadata={"baseline_artifact_id": "NOT-VERIFIED"})
    value = graph(custom_case(tmp_path, amend))
    relation = nodes(value, "uco-core:Relationship")[0]
    assert relation["adfir:recordedTransformationVersion"] == "999"
    assert "adfir:baselineArtifact" not in relation and relation["adfir:executionVerified"] is False


def test_empty_provenance_is_explicit_and_unmapped_files_are_counted(tmp_path):
    def amend(profile, root):
        for field in ("artifacts", "relationships", "ai_records", "tool_records", "analyst_decisions", "comparisons"):
            profile[field] = []
    value = graph(custom_case(tmp_path, amend)); inv = investigation(value)
    assert len(value["@graph"]) == 4 and inv["adfir:artifactCount"] == inv["adfir:recordCount"] == 0
    assert inv["adfir:verifiedPackageFileCount"] == inv["adfir:unmappedPackageFileCount"] > 0
    assert inv["adfir:completeInvestigationExport"] is False


def test_missing_optional_provenance_is_not_accepted_as_exchange(case):
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(case["raw"])) as source, zipfile.ZipFile(target, "w") as out:
        for info in source.infolist():
            if info.filename != PROVENANCE_PATH: out.writestr(info, source.read(info))
    with pytest.raises(ProvenanceError): exchange.export_exchange(target.getvalue(), case["public"], **OPTIONS)


def test_regular_snapshot_reader_and_non_regular_rejection(case, tmp_path):
    assert exchange.read_archive(case["package"]) == case["raw"]
    link = tmp_path / "input-link"; link.symlink_to(case["package"])
    assert exchange.read_archive(link) == case["raw"]
    empty = tmp_path / "empty"; empty.touch()
    fifo = tmp_path / "fifo"; os.mkfifo(fifo)
    for path in (empty, fifo, tmp_path, tmp_path / "absent"):
        with pytest.raises((OSError, ProvenanceError)): exchange.read_archive(path)


def invoke(case, args):
    return subprocess.run([sys.executable, str(Path(cli.__file__)), "--zip", str(case["package"]),
        "--export-public-key", str(case["public"]), "--tenant", TENANT_ID, "--case", CASE_ID, *args],
        capture_output=True, text=True, timeout=30)


def test_cli_export_compare_and_private_exclusive_output(case, tmp_path):
    out = tmp_path / "inventory.jsonld"
    result = invoke(case, ["--out", str(out)])
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "EXPORTED" and summary["output_sha256"] == sha256_bytes(out.read_bytes())
    assert out.stat().st_mode & 0o777 == 0o600
    before = out.read_bytes()
    assert invoke(case, ["--compare", str(out)]).returncode == 0
    assert invoke(case, ["--out", str(out)]).returncode == 1
    assert out.read_bytes() == before
    link = tmp_path / "output-link"; link.symlink_to(out)
    assert invoke(case, ["--out", str(link)]).returncode == 1
    assert out.read_bytes() == before
    changed = json.loads(before); investigation(changed)["adfir:closureAuthorized"] = True
    out.write_text(json.dumps(changed))
    assert invoke(case, ["--compare", str(out)]).returncode == 1


@pytest.mark.parametrize("failure", ["interrupt", "fsync", "missing", "invalid", "required-gate"])
def test_cli_errors_are_redacted_and_never_report_success(case, tmp_path, monkeypatch, capsys, failure):
    out = tmp_path / "SECRET-OUTPUT.jsonld"
    args = ["exchange", "--zip", str(case["package"]), "--export-public-key", str(case["public"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--out", str(out)]
    def fail(*a, **kw): raise OSError("SECRET-FAILURE")
    if failure == "interrupt":
        def interrupt(*a, **kw): raise KeyboardInterrupt()
        monkeypatch.setattr(cli, "read_archive", interrupt)
    elif failure == "fsync": monkeypatch.setattr(cli.os, "fsync", fail)
    elif failure == "missing": case["package"].unlink()
    elif failure == "invalid": case["package"].write_bytes(b"SECRET-INVALID")
    else: args.append("--require-checkpoint-timestamp")
    monkeypatch.setattr(sys, "argv", args)
    code = cli.main(); output = capsys.readouterr()
    assert code == (130 if failure == "interrupt" else 1)
    assert json.loads(output.out)["status"] == ("INTERRUPTED" if code == 130 else "FAIL")
    assert "SECRET" not in output.out and not output.err
    if failure != "fsync": assert not out.exists()
