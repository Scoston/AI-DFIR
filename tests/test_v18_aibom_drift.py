from __future__ import annotations

import copy

import pytest

import v18_ai_ml_bom as bom

T0 = "2026-09-09T18:00:00Z"
T1 = "2026-09-09T19:00:00Z"
H1 = "1" * 64
H2 = "2" * 64


def build_expected():
    model = bom.component("model:primary", "model", "primary-model", version="1", sha256=H1,
                          properties={"role": "primary", "quantization": "none"})
    server = bom.component("mcp:identity", "mcp-server", "identity", version="1")
    policy = bom.component("policy:contain", "policy", "containment", version="7")
    return bom.build("system-1", observed_at=T0, components=[policy, model, server],
                     dependencies=[("model:primary", "mcp:identity"), ("model:primary", "policy:contain")],
                     source_versions={"collector": "1"})


def test_build_is_deterministic_for_component_and_dependency_order():
    a = bom.component("a", "tool", "a")
    b = bom.component("b", "model", "b")
    left = bom.build("sys", observed_at=T0, components=[b, a], dependencies=[("b", "a")])
    right = bom.build("sys", observed_at=T0, components=[a, b], dependencies=[("b", "a")])
    assert left["record_sha256"] == right["record_sha256"]
    assert [x["component_id"] for x in left["components"]] == ["a", "b"]


def test_validate_rejects_tampered_component():
    record = build_expected()
    forged = copy.deepcopy(record)
    forged["components"][0]["name"] = "changed"
    with pytest.raises(ValueError, match="record hash mismatch"):
        bom.validate(forged)


def test_compare_reports_modified_missing_unexpected_and_property_drift():
    expected = build_expected()
    model = bom.component("model:primary", "model", "primary-model", version="2", sha256=H2,
                          properties={"role": "primary", "quantization": "int8", "runtime": "new"})
    server = bom.component("mcp:identity", "mcp-server", "identity", version="1")
    connector = bom.component("connector:new", "connector", "new-connector", version="1")
    observed = bom.build("system-1", observed_at=T1, components=[model, server, connector],
                         dependencies=[("model:primary", "mcp:identity"), ("model:primary", "connector:new")],
                         source_versions={"collector": "2"})
    report = bom.compare(expected, observed)
    assert bom.validate_drift(report, expected=expected, observed=observed)
    by_id = {x["component_id"]: x for x in report["component_changes"]}
    assert by_id["model:primary"]["change_type"] == "modified"
    assert {"version", "sha256", "properties"}.issubset(by_id["model:primary"]["changed_fields"])
    assert by_id["model:primary"]["property_changes"]["added"] == {"runtime": "new"}
    assert by_id["model:primary"]["property_changes"]["modified"]["quantization"] == {"expected": "none", "observed": "int8"}
    assert by_id["policy:contain"]["change_type"] == "missing"
    assert by_id["connector:new"]["change_type"] == "unexpected"
    assert report["summary"]["drift_detected"] is True
    assert report["claims"]["compromise_proven"] is False


def test_dependency_and_source_version_changes_are_explicit():
    expected = build_expected()
    observed = bom.build("system-1", observed_at=T1, components=expected["components"],
                         dependencies=[("model:primary", "mcp:identity")], source_versions={"collector": "2", "schema": "x"})
    report = bom.compare(expected, observed)
    assert report["dependency_changes"]["removed"] == [{"source": "model:primary", "target": "policy:contain"}]
    assert report["source_version_changes"] == {
        "collector": {"expected": "1", "observed": "2"},
        "schema": {"expected": None, "observed": "x"},
    }


def test_identical_inventory_has_no_drift_but_does_not_prove_safety():
    expected = build_expected()
    observed = bom.build("system-1", observed_at=T1, components=expected["components"],
                         dependencies=[(x["source"], x["target"]) for x in expected["dependencies"]],
                         source_versions=expected["source_versions"])
    report = bom.compare(expected, observed)
    assert report["summary"]["drift_detected"] is False
    assert report["component_changes"] == []
    assert report["claims"]["no_drift_proves_safety"] is False


def test_different_system_ids_fail_closed():
    expected = build_expected()
    observed = bom.build("system-2", observed_at=T1, components=expected["components"])
    with pytest.raises(ValueError, match="different system_id"):
        bom.compare(expected, observed)


def test_forged_drift_claim_is_rejected():
    expected = build_expected()
    observed = bom.build("system-1", observed_at=T1, components=expected["components"],
                         dependencies=[(x["source"], x["target"]) for x in expected["dependencies"]],
                         source_versions=expected["source_versions"])
    report = bom.compare(expected, observed)
    forged = copy.deepcopy(report)
    forged["claims"]["compromise_proven"] = True
    with pytest.raises(ValueError, match="compromise_proven"):
        bom.validate_drift(forged)
