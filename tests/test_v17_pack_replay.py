from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from case_export_v17 import verify_case
from evidence_pack_engine import assess, get_pack, load_packs
from evidence_quality import evaluate_gates
from v17_integrity import canonical_json_bytes
from v17_pack_replay import (
    MAX_ARTIFACTS, MAX_GATES, MAX_INPUT_BYTES, MAX_REFERENCES, compare_pack_replay,
    load_replay_document, prepare_replay_input, validate_pack, validate_replay_input,
)
from v17_pack_replay_selftest import export_fixture, synthetic_pack_case
from v17_provenance import ProvenanceError
from v17_provenance_selftest import CASE_ID

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixture(tmp_path):
    return synthetic_pack_case(tmp_path / "case")


def compare(fixture, **options):
    return compare_pack_replay(fixture["input"], fixture["assessment"],
                               **({"case_id": CASE_ID, "expected_pack_sha256": fixture["input"]["pack_sha256"]} | options))


def report(fixture):
    export_fixture(fixture)
    return verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "pack_replay_v17.py"), *map(str, args)], capture_output=True, text=True, timeout=15)


def write_inputs(fixture):
    root = fixture["root"]
    for name, value in (("pack.json", fixture["pack"]), ("assessment.json", fixture["assessment"]), ("input.json", fixture["input"])):
        (root / name).write_bytes(canonical_json_bytes(value))
    return root


def test_signed_case_replays_offline_without_reacquiring_or_extracting(fixture, monkeypatch):
    export_fixture(fixture)
    before = fixture["package"].read_bytes()
    def blocked(*args, **kwargs):
        pytest.fail("replay attempted an external action or raw evidence reassessment")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", blocked)
    monkeypatch.setattr("evidence_quality.assess_artifact", blocked)
    monkeypatch.setattr("evidence_quality.semantic_validate", blocked)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    replay = result["reconstruction"]
    assert replay["deterministic_replay"]["status"] == "PASS"
    assert not replay["model_invoked"] and not replay["tools_executed"]
    assert fixture["package"].read_bytes() == before


def test_replay_pass_can_reproduce_an_unsupported_conclusion(fixture):
    result = compare(fixture)
    assert result["status"] == "PASS"
    assert [gate["status"] for gate in result["gate_results"]] == ["supported", "not_supported"]
    impact = result["gate_results"][1]
    assert not impact["missing"]
    assert impact["insufficient_quality"] == [{"artifact": "target", "required_quality": "CORRELATED", "actual": ["MISSING", "VALIDATED"]}]
    assert result["recorded_quality_only"]
    for name in ("raw_evidence_revalidated", "pack_approval_verified", "closure_authorized", "network_required"):
        assert result[name] is False


@pytest.mark.parametrize("mutation", [
    lambda a: a["conclusion_gates"][1].update(status="supported"),
    lambda a: a.update(mandatory_qualified=2), lambda a: a.update(mandatory_percent=100),
    lambda a: a["quality_scale"].update(CONFLICTING=4), lambda a: a.update(mandatory_total=True),
    lambda a: a["conclusion_gates"].reverse(),
])
def test_incorrect_preserved_gate_summary_keeps_integrity_but_fails_replay(fixture, mutation):
    mutation(fixture["assessment"])
    result = report(fixture)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    replay = result["reconstruction"]["deterministic_replay"]
    assert replay["status"] == "FAIL"
    row = replay["transforms"][0]
    assert row["recorded_summary_sha256"] != row["replayed_summary_sha256"]


@pytest.mark.parametrize("quality,supported", [("MISSING", False), ("PRESENT_UNVALIDATED", False), ("VALIDATED", True),
    ("CORRELATED", True), ("AUTHORITATIVE", True), ("CONFLICTING", False), ("STALE", False), ("INCOMPLETE", False)])
def test_quality_states_preserve_missing_and_negative_semantics(fixture, quality, supported):
    rows = [{"id": a["id"], "priority": a["priority"], "quality": quality if a["id"] == "source" else "MISSING"}
            for a in fixture["pack"]["artifacts"]]
    result = evaluate_gates(fixture["pack"], rows)
    assert (result["conclusion_gates"][0]["status"] == "supported") is supported
    assert result["mandatory_qualified"] == int(supported) and result["mandatory_total"] == 2
    if quality == "MISSING":
        assert result["conclusion_gates"][0]["missing"] == ["source"]
    elif not supported:
        assert result["conclusion_gates"][0]["insufficient_quality"][0]["actual"] == [quality]


@pytest.mark.parametrize("logic,alias,expected", [("all", "VALIDATED", "not_supported"), ("all", "CORRELATED", "supported"),
    ("all", "CONFLICTING", "not_supported"), ("any", "MISSING", "supported")])
def test_aliases_any_logic_and_per_requirement_quality_overrides(fixture, logic, alias, expected):
    pack = copy.deepcopy(fixture["pack"])
    pack["conclusion_gates"][1]["logic"] = logic
    rows = [{"id": a["id"], "priority": a["priority"], "quality": {"source": "VALIDATED", "target": "MISSING", "corroboration": alias}[a["id"]]}
            for a in pack["artifacts"]]
    result = evaluate_gates(validate_pack(pack), rows)
    assert result["conclusion_gates"][1]["status"] == expected
    assert result["mandatory_qualified"] == 1  # Aliases do not fill the mandatory inventory.


def test_unknown_rule_reference_is_missing_without_implicit_alias_resolution(fixture):
    fixture["pack"]["conclusion_gates"][0]["requires"] = ["not_declared"]
    result = evaluate_gates(validate_pack(fixture["pack"]), fixture["assessment"]["artifacts"])
    assert result["conclusion_gates"][0]["status"] == "not_supported"
    assert result["conclusion_gates"][0]["missing"] == ["not_declared"]


def test_all_catalog_packs_capture_complete_recorded_states_without_catalog_lookup(monkeypatch):
    retained = []
    for pack in load_packs():
        assessment = assess(pack, ROOT / "tests/fixtures/evidence_packs" / pack["id"])
        value = prepare_replay_input(pack, assessment, case_id="CASE-CATALOG-SYNTHETIC")
        retained.append((value, assessment))
    assert len(retained) == 111
    monkeypatch.setattr("evidence_pack_engine.load_packs", lambda *args: pytest.fail("replay read the current catalog"))
    monkeypatch.setattr("evidence_pack_engine.get_pack", lambda *args: pytest.fail("replay resolved a current pack"))
    for value, assessment in retained:
        assert "_path" not in value["pack"]
        result = compare_pack_replay(value, assessment, case_id="CASE-CATALOG-SYNTHETIC", expected_pack_sha256=value["pack_sha256"])
        assert result["status"] == "PASS"


def test_kubernetes_pack_has_distinct_context_and_required_network_identity():
    pack = get_pack("microsoft.ExposedKubernetesService.AI")
    by = {a["id"]: a for a in pack["artifacts"]}
    assert len(by) == len(pack["artifacts"])
    assert by["network_context"]["priority"] == "conditional" and by["network"]["priority"] == "mandatory"
    rows = [{"id": a["id"], "priority": a["priority"], "quality": "AUTHORITATIVE" if a["id"] == "network_context" else "MISSING"}
            for a in pack["artifacts"]]
    gates = evaluate_gates(pack, rows)["conclusion_gates"]
    assert next(g for g in gates if g["id"] == "external_access_confirmed")["status"] == "not_supported"


def test_capture_preserves_incorrect_summary_and_does_not_mutate_sources(fixture):
    fixture["assessment"]["mandatory_qualified"] = 100
    before = copy.deepcopy((fixture["pack"], fixture["assessment"]))
    value = prepare_replay_input(fixture["pack"], fixture["assessment"], case_id=CASE_ID)
    result = compare_pack_replay(value, fixture["assessment"], case_id=CASE_ID, expected_pack_sha256=value["pack_sha256"])
    assert result["status"] == "FAIL" and before == (fixture["pack"], fixture["assessment"])


def test_paths_formatting_and_unused_assessment_details_do_not_change_gate_comparison(fixture):
    original = compare(fixture)
    fixture["assessment"] = json.loads(json.dumps(fixture["assessment"], indent=3))
    fixture["assessment"]["case_root"] = "/another/retained/location"
    fixture["assessment"]["artifacts"][0]["match_assessments"] = []
    fixture["assessment"]["notes"] = ["A recorded detail outside this calculation"]
    fixture["assessment"]["artifacts"].reverse()
    fixture["input"]["quality_states"].reverse()
    assert compare(fixture) == original


@pytest.mark.parametrize("change", [
    lambda p: p.update(schema="unsupported"), lambda p: p.update(command="arbitrary.module"),
    lambda p: p.update(_path="/unapproved/catalog"), lambda p: p.update(id="../escape"),
    lambda p: p.update(artifacts=[]), lambda p: p.update(artifacts=p["artifacts"] * (MAX_ARTIFACTS + 1)),
    lambda p: p["artifacts"].append(p["artifacts"][0]), lambda p: p["artifacts"][0].update(priority="automatically_trusted"),
    lambda p: p["artifacts"][0].update(executor="arbitrary.module"), lambda p: p.update(conclusion_gates=[]),
    lambda p: p.update(conclusion_gates=p["conclusion_gates"] * (MAX_GATES + 1)),
    lambda p: p["conclusion_gates"].append(p["conclusion_gates"][0]),
    lambda p: p["conclusion_gates"][0].update(requires=[]), lambda p: p["conclusion_gates"][0].update(requires=["source", "source"]),
    lambda p: p["conclusion_gates"][0].update(logic="execute"), lambda p: p["conclusion_gates"][0].update(min_quality="MISSING"),
    lambda p: p["conclusion_gates"][0].update(min_quality="CONFLICTING"), lambda p: p.update(mandatory_min_quality="UNRECOGNIZED"),
    lambda p: p["conclusion_gates"][0].update(allow_aliases={"other": ["source"]}),
    lambda p: p["conclusion_gates"][0].update(allow_aliases={"source": []}),
    lambda p: p["conclusion_gates"][0].update(quality_requires={"other": "VALIDATED"}),
    lambda p: p["conclusion_gates"][0].update(quality_requires={"source": "MISSING"}),
    lambda p: p["conclusion_gates"][0].update(allow_aliases={"source": ["bad\nlog"]}),
])
def test_ambiguous_or_unsupported_rules_fail_closed(fixture, change):
    change(fixture["pack"])
    with pytest.raises(ProvenanceError):
        validate_pack(fixture["pack"])


def test_total_reference_budget_rejects_excess_work_before_calculation(fixture):
    pack = fixture["pack"]
    refs = [f"required-{i}" for i in range(MAX_ARTIFACTS)]
    pack["conclusion_gates"] = [{"id": f"gate-{i}", "title": "Synthetic budget case", "requires": refs}
                                for i in range(MAX_REFERENCES // MAX_ARTIFACTS + 1)]
    with pytest.raises(ProvenanceError, match="references exceed"):
        validate_pack(pack)


@pytest.mark.parametrize("change", [
    lambda v: v.update(schema="other"), lambda v: v.update(command="unapproved"), lambda v: v.update(case_id="OTHER"),
    lambda v: v.update(pack_sha256="0" * 64), lambda v: v["pack"].update(title="Changed rules"),
    lambda v: v["quality_states"].pop(), lambda v: v["quality_states"].append(v["quality_states"][0]),
    lambda v: v["quality_states"][0].update(quality="UNKNOWN"), lambda v: v["quality_states"][0].update(quality=True),
    lambda v: v["quality_states"][0].update(priority="optional"), lambda v: v["quality_states"][0].update(id="other"),
    lambda v: v["quality_states"][1].update(id="source"),
])
def test_case_pack_and_complete_quality_binding_is_required(fixture, change):
    pin = fixture["input"]["pack_sha256"]
    change(fixture["input"])
    with pytest.raises(ProvenanceError):
        validate_replay_input(fixture["input"], case_id=CASE_ID, expected_pack_sha256=pin)


@pytest.mark.parametrize("pin", [None, "", "A" * 64, "0" * 64, [], True])
def test_explicit_pack_pin_is_strict_and_cannot_be_adopted_from_input(fixture, pin):
    with pytest.raises(ProvenanceError):
        compare(fixture, expected_pack_sha256=pin)


@pytest.mark.parametrize("change", [
    lambda a: a.update(schema="other"), lambda a: a.update(pack_id="OTHER"), lambda a: a.pop("mandatory_qualified"),
    lambda a: a["artifacts"].pop(), lambda a: a["artifacts"][0].update(quality="AUTHORITATIVE"),
    lambda a: a["artifacts"][0].update(priority="optional"), lambda a: a["artifacts"][1].update(id="source"),
])
def test_recorded_assessment_must_bind_the_same_pack_and_quality_inputs(fixture, change):
    change(fixture["assessment"])
    with pytest.raises(ProvenanceError):
        compare(fixture)


@pytest.mark.parametrize("metadata", [{}, {"pack_sha256": "0" * 64}, {"pack_sha256": "0" * 64, "command": "not-allowed"}])
def test_signed_relationship_metadata_cannot_omit_or_redirect_pack_binding(fixture, metadata):
    fixture["metadata"] = metadata
    result = report(fixture)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("name,version", [("evidence_quality.evaluate_gates", "future"), ("arbitrary.module.command", "1.7")])
def test_unknown_adapters_remain_unsupported_without_execution(fixture, name, version):
    fixture.update(transformation=name, version=version)
    result = report(fixture)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


def test_modified_archive_is_not_replayed(fixture, monkeypatch):
    export_fixture(fixture)
    with zipfile.ZipFile(fixture["package"], "a") as archive:
        archive.writestr("unlisted.json", b"{}")
    monkeypatch.setattr("case_export_v17.reconstruct", lambda *a, **k: pytest.fail("unverified archive reconstructed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert not result["valid"] and "reconstruction" not in result


@pytest.mark.parametrize("raw", [b"", b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'[' * 2000])
def test_json_document_loading_rejects_ambiguity_and_malformed_data(tmp_path, raw):
    path = tmp_path / "invalid.json"
    path.write_bytes(raw)
    with pytest.raises(ProvenanceError):
        load_replay_document(path, limit=MAX_INPUT_BYTES)


def test_oversized_input_is_rejected(fixture, tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(ProvenanceError):
        load_replay_document(path, limit=MAX_INPUT_BYTES)
    fixture["input"]["pack"]["description"] = "x" * MAX_INPUT_BYTES
    with pytest.raises(ProvenanceError):
        compare(fixture)


def test_signed_archive_enforces_raw_snapshot_limit_before_json_parsing(fixture):
    fixture["input_bytes"] = canonical_json_bytes(fixture["input"]) + b" " * MAX_INPUT_BYTES
    result = report(fixture)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("required", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_required_independent_case_gates_still_block_reconstruction(fixture, required):
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{required: True})
    assert not result["valid"] and "reconstruction" not in result


@pytest.mark.parametrize("kind", ["directory", "symlink", "missing"])
def test_local_inputs_must_be_regular_files(tmp_path, kind):
    path = tmp_path / "document.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text("{}")
        path.symlink_to(target)
    with pytest.raises(ProvenanceError):
        load_replay_document(path, limit=MAX_INPUT_BYTES)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_fifo_is_rejected_without_blocking(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path)
    with pytest.raises(ProvenanceError):
        load_replay_document(path, limit=MAX_INPUT_BYTES)


def test_prepare_and_verify_cli_preserve_original_assessment(fixture):
    root = write_inputs(fixture)
    output = root / "captured.json"
    original = (root / "assessment.json").read_bytes()
    result = cli("prepare", "--pack", root / "pack.json", "--assessment", root / "assessment.json", "--case", CASE_ID, "--out", output)
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "PREPARED"
    assert not json.loads(result.stdout)["recorded_gate_result_verified"]
    checked = cli("verify", "--input", output, "--assessment", root / "assessment.json", "--case", CASE_ID,
                  "--expected-pack-sha256", fixture["input"]["pack_sha256"])
    assert checked.returncode == 0 and json.loads(checked.stdout)["status"] == "PASS"
    assert (root / "assessment.json").read_bytes() == original
    again = cli("prepare", "--pack", root / "pack.json", "--assessment", root / "assessment.json", "--case", CASE_ID, "--out", root / "assessment.json")
    assert again.returncode == 1 and (root / "assessment.json").read_bytes() == original


def test_failed_gate_replay_has_nonzero_standalone_and_case_cli_exit(fixture):
    fixture["assessment"]["mandatory_qualified"] = 99
    root = write_inputs(fixture)
    result = cli("verify", "--input", root / "input.json", "--assessment", root / "assessment.json", "--case", CASE_ID,
                 "--expected-pack-sha256", fixture["input"]["pack_sha256"])
    assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL"
    export_fixture(fixture)
    case = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                           "--export-public-key", str(fixture["public"]), "--replay-transforms"], capture_output=True, text=True, timeout=15)
    checked = json.loads(case.stdout)
    assert case.returncode == 1 and checked["valid"] and checked["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_cli_invalid_input_is_redacted_and_does_not_create_output(fixture):
    root = write_inputs(fixture)
    (root / "pack.json").write_text('{"private-content":invalid}')
    output = root / "must-not-exist.json"
    result = cli("prepare", "--pack", root / "pack.json", "--assessment", root / "assessment.json", "--case", CASE_ID, "--out", output)
    assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL" and not output.exists()
    assert "private-content" not in result.stdout and str(root) not in result.stdout and not result.stderr
