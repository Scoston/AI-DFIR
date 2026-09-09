"""AI/ML bill-of-materials support for AI-DFIR v1.8.

The internal inventory is evidence-oriented. ``to_cyclonedx_1_7`` creates a
conservative CycloneDX-shaped projection but does not claim schema conformance
unless an external validator is run. Drift compares two retained inventories; it
does not treat change as proof of compromise.
"""
from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import datetime
from typing import Any, Iterable

from v18_agent_execution_record import canonical_bytes, sha256_bytes

SCHEMA = "ai-dfir/ai-ml-bom/v1.8"
DRIFT_SCHEMA = "ai-dfir/ai-ml-bom-drift/v1.8"
CYCLONEDX_VERSION = "1.7"
COMPONENT_KINDS = {"model", "tokenizer", "adapter", "runtime", "tool", "mcp-server", "connector", "dataset", "retrieval-store", "embedding-model", "policy", "container", "library", "skill"}
COMPONENT_FIELDS = ("kind", "name", "version", "sha256", "source", "properties")


def _time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("observed_at must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid observed_at") from exc
    return value


def _sha(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("sha256 must be lowercase hexadecimal SHA-256")
    return value


def component(component_id: str, kind: str, name: str, *, version: str | None = None,
              sha256: str | None = None, source: str | None = None,
              properties: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(component_id, str) or not component_id or kind not in COMPONENT_KINDS or not isinstance(name, str) or not name:
        raise ValueError("invalid component identity")
    _sha(sha256)
    if version is not None and not isinstance(version, str):
        raise ValueError("version must be a string or null")
    if source is not None and not isinstance(source, str):
        raise ValueError("source must be a string or null")
    if properties is not None and not isinstance(properties, dict):
        raise ValueError("properties must be an object")
    return {"component_id": component_id, "kind": kind, "name": name, "version": version,
            "sha256": sha256, "source": source, "properties": deepcopy(properties or {})}


def build(system_id: str, *, observed_at: str, components: Iterable[dict[str, Any]],
          dependencies: Iterable[tuple[str, str]] = (), source_versions: dict[str, str] | None = None) -> dict[str, Any]:
    if not isinstance(system_id, str) or not system_id:
        raise ValueError("system_id is required")
    _time(observed_at)
    components = [deepcopy(x) for x in components]
    normalized: list[dict[str, Any]] = []
    for item in components:
        if not isinstance(item, dict):
            raise ValueError("component must be an object")
        normalized.append(component(item.get("component_id"), item.get("kind"), item.get("name"),
                                    version=item.get("version"), sha256=item.get("sha256"), source=item.get("source"),
                                    properties=item.get("properties")))
    ids = [x["component_id"] for x in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("component ids must be unique")
    normalized.sort(key=lambda x: x["component_id"])
    known = set(ids)
    deps: list[dict[str, str]] = []
    seen_deps: set[tuple[str, str]] = set()
    for source, target in dependencies:
        if source not in known or target not in known:
            raise ValueError("dependency references unknown component")
        pair = (source, target)
        if pair in seen_deps:
            continue
        seen_deps.add(pair)
        deps.append({"source": source, "target": target})
    deps.sort(key=lambda x: (x["source"], x["target"]))
    versions = deepcopy(source_versions or {})
    if not isinstance(versions, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in versions.items()):
        raise ValueError("source_versions must map strings to strings")
    record = {"schema": SCHEMA, "system_id": system_id, "observed_at": observed_at,
              "source_versions": versions, "components": normalized,
              "dependencies": deps,
              "claims": {"inventory_complete": False, "component_authenticity_verified": False,
                         "cyclonedx_conformance_verified": False}}
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    validate(record)
    return record


def validate(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise ValueError("unsupported AI/ML BOM schema")
    if not isinstance(record.get("system_id"), str) or not record["system_id"]:
        raise ValueError("system_id is required")
    _time(record.get("observed_at"))
    versions = record.get("source_versions")
    if not isinstance(versions, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in versions.items()):
        raise ValueError("invalid source_versions")
    items = record.get("components")
    if not isinstance(items, list):
        raise ValueError("components must be an array")
    ids: set[str] = set()
    for item in items:
        rebuilt = component(item.get("component_id"), item.get("kind"), item.get("name"),
                            version=item.get("version"), sha256=item.get("sha256"), source=item.get("source"),
                            properties=item.get("properties"))
        if set(item) != set(rebuilt):
            raise ValueError("unexpected component fields")
        if rebuilt["component_id"] in ids:
            raise ValueError("duplicate component_id")
        ids.add(rebuilt["component_id"])
    deps = record.get("dependencies")
    if not isinstance(deps, list):
        raise ValueError("dependencies must be an array")
    seen: set[tuple[str, str]] = set()
    for dep in deps:
        if not isinstance(dep, dict) or set(dep) != {"source", "target"}:
            raise ValueError("invalid dependency")
        pair = (dep["source"], dep["target"])
        if pair[0] not in ids or pair[1] not in ids or pair in seen:
            raise ValueError("invalid or duplicate dependency")
        seen.add(pair)
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("claims missing")
    for key in ("inventory_complete", "component_authenticity_verified", "cyclonedx_conformance_verified"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(record); digest = unsigned.pop("record_sha256", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("AI/ML BOM record hash mismatch")
    return True


def _property_changes(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    eprops, oprops = expected.get("properties", {}), observed.get("properties", {})
    ekeys, okeys = set(eprops), set(oprops)
    return {
        "added": {key: deepcopy(oprops[key]) for key in sorted(okeys - ekeys)},
        "removed": {key: deepcopy(eprops[key]) for key in sorted(ekeys - okeys)},
        "modified": {key: {"expected": deepcopy(eprops[key]), "observed": deepcopy(oprops[key])}
                     for key in sorted(ekeys & okeys) if eprops[key] != oprops[key]},
    }


def compare(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Compare two bound inventories without inferring compromise from drift."""
    validate(expected); validate(observed)
    if expected["system_id"] != observed["system_id"]:
        raise ValueError("cannot compare different system_id values")
    exp = {item["component_id"]: item for item in expected["components"]}
    obs = {item["component_id"]: item for item in observed["components"]}
    changes: list[dict[str, Any]] = []
    for component_id in sorted(set(exp) | set(obs)):
        if component_id not in obs:
            changes.append({"component_id": component_id, "change_type": "missing",
                            "expected": deepcopy(exp[component_id]), "observed": None, "changed_fields": []})
            continue
        if component_id not in exp:
            changes.append({"component_id": component_id, "change_type": "unexpected",
                            "expected": None, "observed": deepcopy(obs[component_id]), "changed_fields": []})
            continue
        changed = [field for field in COMPONENT_FIELDS if exp[component_id].get(field) != obs[component_id].get(field)]
        if changed:
            entry = {"component_id": component_id, "change_type": "modified",
                     "expected": deepcopy(exp[component_id]), "observed": deepcopy(obs[component_id]),
                     "changed_fields": changed}
            if "properties" in changed:
                entry["property_changes"] = _property_changes(exp[component_id], obs[component_id])
            changes.append(entry)

    exp_deps = {(x["source"], x["target"]) for x in expected["dependencies"]}
    obs_deps = {(x["source"], x["target"]) for x in observed["dependencies"]}
    dependency_changes = {
        "added": [{"source": s, "target": t} for s, t in sorted(obs_deps - exp_deps)],
        "removed": [{"source": s, "target": t} for s, t in sorted(exp_deps - obs_deps)],
    }
    version_keys = set(expected["source_versions"]) | set(observed["source_versions"])
    source_version_changes = {
        key: {"expected": expected["source_versions"].get(key), "observed": observed["source_versions"].get(key)}
        for key in sorted(version_keys)
        if expected["source_versions"].get(key) != observed["source_versions"].get(key)
    }
    drift_detected = bool(changes or dependency_changes["added"] or dependency_changes["removed"] or source_version_changes)
    report = {
        "schema": DRIFT_SCHEMA,
        "system_id": expected["system_id"],
        "expected_record_sha256": expected["record_sha256"],
        "observed_record_sha256": observed["record_sha256"],
        "expected_observed_at": expected["observed_at"],
        "observed_observed_at": observed["observed_at"],
        "component_changes": changes,
        "dependency_changes": dependency_changes,
        "source_version_changes": source_version_changes,
        "summary": {
            "expected_components": len(exp), "observed_components": len(obs),
            "component_changes": len(changes),
            "dependency_changes": len(dependency_changes["added"]) + len(dependency_changes["removed"]),
            "source_version_changes": len(source_version_changes),
            "drift_detected": drift_detected,
        },
        "claims": {
            "expected_inventory_complete": False,
            "observed_inventory_complete": False,
            "component_authenticity_verified": False,
            "compromise_proven": False,
            "no_drift_proves_safety": False,
        },
    }
    report["report_sha256"] = sha256_bytes(canonical_bytes(report))
    validate_drift(report, expected=expected, observed=observed)
    return report


def validate_drift(report: dict[str, Any], *, expected: dict[str, Any] | None = None,
                   observed: dict[str, Any] | None = None) -> bool:
    if not isinstance(report, dict) or report.get("schema") != DRIFT_SCHEMA:
        raise ValueError("unsupported AI/ML BOM drift schema")
    claims = report.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("drift claims missing")
    for key in ("expected_inventory_complete", "observed_inventory_complete", "component_authenticity_verified", "compromise_proven", "no_drift_proves_safety"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    if expected is not None:
        validate(expected)
        if report.get("expected_record_sha256") != expected["record_sha256"]:
            raise ValueError("expected BOM binding mismatch")
    if observed is not None:
        validate(observed)
        if report.get("observed_record_sha256") != observed["record_sha256"]:
            raise ValueError("observed BOM binding mismatch")
    unsigned = deepcopy(report); digest = unsigned.pop("report_sha256", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("AI/ML BOM drift report hash mismatch")
    return True


def to_cyclonedx_1_7(record: dict[str, Any]) -> dict[str, Any]:
    validate(record)
    components = []
    for item in record.get("components", []):
        props = [{"name": "ai-dfir:kind", "value": item["kind"]}]
        if item.get("source"):
            props.append({"name": "ai-dfir:source", "value": item["source"]})
        for key, value in sorted(item.get("properties", {}).items()):
            props.append({"name": f"ai-dfir:{key}", "value": str(value)})
        cdx = {"type": "machine-learning-model" if item["kind"] in {"model", "embedding-model"} else "application",
               "bom-ref": item["component_id"], "name": item["name"], "properties": props}
        if item.get("version") is not None:
            cdx["version"] = item["version"]
        if item.get("sha256"):
            cdx["hashes"] = [{"alg": "SHA-256", "content": item["sha256"]}]
        components.append(cdx)
    dep_map: dict[str, list[str]] = {item["component_id"]: [] for item in record.get("components", [])}
    for dep in record.get("dependencies", []):
        dep_map[dep["source"]].append(dep["target"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, record['record_sha256'])}",
        "version": 1,
        "metadata": {"properties": [
            {"name": "ai-dfir:source-record-sha256", "value": record["record_sha256"]},
            {"name": "ai-dfir:conformance-verified", "value": "false"},
        ]},
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(dep_map.items())],
    }
