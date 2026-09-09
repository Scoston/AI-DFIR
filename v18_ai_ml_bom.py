"""AI/ML bill-of-materials support for AI-DFIR v1.8.

The internal inventory is evidence-oriented. ``to_cyclonedx_1_7`` creates a
conservative CycloneDX-shaped projection but does not claim schema conformance
unless an external validator is run.
"""
from __future__ import annotations

import uuid
from copy import deepcopy
from typing import Any, Iterable

from v18_agent_execution_record import canonical_bytes, sha256_bytes

SCHEMA = "ai-dfir/ai-ml-bom/v1.8"
CYCLONEDX_VERSION = "1.7"
COMPONENT_KINDS = {"model", "tokenizer", "adapter", "runtime", "tool", "mcp-server", "connector", "dataset", "retrieval-store", "embedding-model", "policy", "container", "library", "skill"}


def component(component_id: str, kind: str, name: str, *, version: str | None = None,
              sha256: str | None = None, source: str | None = None,
              properties: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(component_id, str) or not component_id or kind not in COMPONENT_KINDS or not isinstance(name, str) or not name:
        raise ValueError("invalid component identity")
    if sha256 is not None and (not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256)):
        raise ValueError("sha256 must be lowercase hexadecimal SHA-256")
    return {"component_id": component_id, "kind": kind, "name": name, "version": version,
            "sha256": sha256, "source": source, "properties": deepcopy(properties or {})}


def build(system_id: str, *, observed_at: str, components: Iterable[dict[str, Any]],
          dependencies: Iterable[tuple[str, str]] = (), source_versions: dict[str, str] | None = None) -> dict[str, Any]:
    components = [deepcopy(x) for x in components]
    ids = [x.get("component_id") for x in components]
    if len(ids) != len(set(ids)) or any(not x for x in ids):
        raise ValueError("component ids must be unique and non-empty")
    known = set(ids)
    deps = []
    for source, target in dependencies:
        if source not in known or target not in known:
            raise ValueError("dependency references unknown component")
        deps.append({"source": source, "target": target})
    record = {"schema": SCHEMA, "system_id": system_id, "observed_at": observed_at,
              "source_versions": deepcopy(source_versions or {}), "components": components,
              "dependencies": deps,
              "claims": {"inventory_complete": False, "component_authenticity_verified": False,
                         "cyclonedx_conformance_verified": False}}
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    return record


def to_cyclonedx_1_7(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("schema") != SCHEMA:
        raise ValueError("unsupported AI/ML BOM schema")
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
