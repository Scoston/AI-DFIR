"""Bounded offline reproduction of Evidence Pack gates from recorded ratings.

Pack rules are data. Replay never acquires evidence, loads pack-selected code,
revalidates raw evidence quality, or authorizes an investigative conclusion.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from evidence_quality import QUALITY_ORDER, evaluate_gates
from v17_integrity import canonical_json_bytes, sha256_object
from v17_provenance import ProvenanceError
from v17_reconstruction import strict_json

INPUT_SCHEMA = "ai-dfir/evidence-pack-replay-input/v1.7"
REPORT_SCHEMA = "ai-dfir/evidence-pack-gate-replay/v1.7"
TRANSFORMATION = "evidence_quality.evaluate_gates"
TRANSFORMATION_VERSION = "1.7"
MAX_INPUT_BYTES = 2 * 1024**2
MAX_ASSESSMENT_BYTES = 16 * 1024**2
MAX_ARTIFACTS = 256
MAX_GATES = 128
MAX_REFERENCES = 4096
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMAS = {f"ai-dfir/evidence-pack/v{v}" for v in ("0.8", "0.9", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6")}
_PACK_FIELDS = {"schema", "id", "title", "artifacts", "conclusion_gates", "mandatory_min_quality", "description",
                "forensic_modes", "incident_type", "mappings", "match", "notes", "platform", "questions",
                "related_packs", "sources", "vendor", "vendor_severity"}
_ARTIFACT_FIELDS = {"id", "title", "priority", "category", "collection_guidance", "condition", "locations",
                    "presence_patterns", "rationale", "validation"}
_GATE_FIELDS = {"id", "title", "requires", "logic", "min_quality", "quality_requires", "allow_aliases"}
_MINIMUMS = {"PRESENT_UNVALIDATED", "VALIDATED", "CORRELATED", "AUTHORITATIVE"}
_SUMMARY_FIELDS = ("mandatory_min_quality", "mandatory_qualified", "mandatory_total", "mandatory_percent",
                   "conclusion_gates", "quality_scale")


def _require(condition, message):
    if not condition:
        raise ProvenanceError(message)


def _snapshot(value: Any, limit: int):
    try:
        raw = canonical_json_bytes(value)
        _require(0 < len(raw) <= limit, "Evidence Pack replay input exceeds its byte limit")
        return strict_json(raw)
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ProvenanceError("invalid or oversized Evidence Pack replay JSON") from exc


def _identifier(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 4096 and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def _minimum(value):
    return isinstance(value, str) and value in _MINIMUMS


def _references(value):
    _require(isinstance(value, list) and 1 <= len(value) <= MAX_ARTIFACTS
             and all(_identifier(item) for item in value) and len(set(value)) == len(value),
             "gate references must be unique nonempty identifiers")
    return value


def validate_pack(pack: Any) -> dict:
    pack = _snapshot(pack, MAX_INPUT_BYTES)
    _require(isinstance(pack, dict) and {"schema", "id", "title", "artifacts", "conclusion_gates"}.issubset(pack)
             and set(pack).issubset(_PACK_FIELDS), "unsupported Evidence Pack fields")
    _require(isinstance(pack["schema"], str) and pack["schema"] in _SCHEMAS and _identifier(pack["id"])
             and _text(pack["title"]), "unsupported Evidence Pack identity or schema")
    _require(_minimum(pack.get("mandatory_min_quality", "VALIDATED")), "invalid mandatory minimum quality")
    artifacts = pack["artifacts"]
    _require(isinstance(artifacts, list) and 1 <= len(artifacts) <= MAX_ARTIFACTS, "invalid Evidence Pack artifact count")
    ids = set()
    for artifact in artifacts:
        _require(isinstance(artifact, dict) and {"id", "title", "priority"}.issubset(artifact)
                 and set(artifact).issubset(_ARTIFACT_FIELDS), "unsupported artifact rule fields")
        ident = artifact["id"]
        _require(_identifier(ident) and ident not in ids and _text(artifact["title"]), "invalid or duplicate artifact identity")
        ids.add(ident)
        _require(isinstance(artifact["priority"], str) and artifact["priority"] in {"mandatory", "conditional", "optional"},
                 "invalid artifact priority")
    gates = pack["conclusion_gates"]
    _require(isinstance(gates, list) and 1 <= len(gates) <= MAX_GATES, "invalid Evidence Pack gate count")
    ids, count = set(), 0
    for gate in gates:
        _require(isinstance(gate, dict) and {"id", "title", "requires"}.issubset(gate)
                 and set(gate).issubset(_GATE_FIELDS), "unsupported gate rule fields")
        ident = gate["id"]
        _require(_identifier(ident) and ident not in ids and _text(gate["title"]), "invalid or duplicate gate identity")
        ids.add(ident)
        _require(isinstance(gate.get("logic", "all"), str) and gate.get("logic", "all") in {"all", "any"}, "unsupported gate logic")
        _require(_minimum(gate.get("min_quality", "VALIDATED")), "invalid gate minimum quality")
        requires = _references(gate["requires"])
        count += len(requires)
        aliases, overrides = gate.get("allow_aliases", {}), gate.get("quality_requires", {})
        _require(isinstance(aliases, dict) and set(aliases).issubset(requires), "aliases require an explicit gate requirement")
        for values in aliases.values():
            count += len(_references(values))
        _require(isinstance(overrides, dict) and set(overrides).issubset(requires)
                 and all(_minimum(v) for v in overrides.values()), "invalid per-requirement quality override")
        _require(count <= MAX_REFERENCES, "Evidence Pack gate references exceed replay limit")
    return pack


def _states(value, pack):
    _require(isinstance(value, list) and len(value) == len(pack["artifacts"]), "one quality state is required for every pack artifact")
    by = {}
    for row in value:
        _require(isinstance(row, dict) and set(row) == {"id", "quality"} and _identifier(row["id"])
                 and row["id"] not in by and isinstance(row["quality"], str) and row["quality"] in QUALITY_ORDER,
                 "invalid, duplicate, or unknown recorded quality state")
        by[row["id"]] = row["quality"]
    _require(set(by) == {a["id"] for a in pack["artifacts"]}, "recorded qualities do not match the complete pack artifact set")
    return [{"id": a["id"], "quality": by[a["id"]]} for a in pack["artifacts"]]


def _assessment(value, pack):
    value = _snapshot(value, MAX_ASSESSMENT_BYTES)
    _require(isinstance(value, dict) and isinstance(value.get("schema"), str)
             and value["schema"] in {"ai-dfir/evidence-assessment/v1.1", "ai-dfir/evidence-quality-assessment/v1.2"}
             and value.get("pack_id") == pack["id"] and value.get("pack_title") == pack["title"]
             and all(name in value for name in _SUMMARY_FIELDS), "assessment identity or gate summary is incomplete")
    rows = value.get("artifacts")
    _require(isinstance(rows, list) and len(rows) == len(pack["artifacts"]), "assessment artifact set is incomplete")
    priorities = {a["id"]: a["priority"] for a in pack["artifacts"]}
    states = []
    for row in rows:
        _require(isinstance(row, dict) and _identifier(row.get("id")) and row["id"] in priorities
                 and row.get("priority") == priorities[row["id"]], "assessment artifact differs from retained pack rule")
        states.append({"id": row["id"], "quality": row.get("quality")})
    return value, _states(states, pack)


def prepare_replay_input(pack: Any, assessment: Any, *, case_id: str) -> dict:
    """Capture exact pack rules and ratings; do not repair a recorded gate result."""
    # load_packs() attaches a local discovery path that is not pack content.
    if isinstance(pack, dict):
        pack = {key: value for key, value in pack.items() if key != "_path"}
    pack = validate_pack(pack)
    _require(_text(case_id), "explicit case identity is required")
    _, states = _assessment(assessment, pack)
    return _snapshot({"schema": INPUT_SCHEMA, "case_id": case_id, "pack": pack,
                      "pack_sha256": sha256_object(pack), "quality_states": states}, MAX_INPUT_BYTES)


def validate_replay_input(value: Any, *, case_id: str, expected_pack_sha256: str) -> dict:
    value = _snapshot(value, MAX_INPUT_BYTES)
    _require(isinstance(value, dict) and set(value) == {"schema", "case_id", "pack", "pack_sha256", "quality_states"}
             and value["schema"] == INPUT_SCHEMA, "unsupported Evidence Pack replay snapshot")
    _require(_text(case_id) and value["case_id"] == case_id, "Evidence Pack replay case mismatch")
    _require(isinstance(expected_pack_sha256, str) and _HEX.fullmatch(expected_pack_sha256) is not None,
             "an explicit canonical pack SHA-256 pin is required")
    pack = validate_pack(value["pack"])
    _require(value["pack_sha256"] == expected_pack_sha256 == sha256_object(pack), "Evidence Pack digest mismatch")
    value["quality_states"] = _states(value["quality_states"], pack)
    return value


def compare_pack_replay(value: Any, assessment: Any, *, case_id: str, expected_pack_sha256: str) -> dict:
    value = validate_replay_input(value, case_id=case_id, expected_pack_sha256=expected_pack_sha256)
    pack = value["pack"]
    assessment, states = _assessment(assessment, pack)
    _require(states == value["quality_states"], "assessment quality states differ from retained replay input")
    by = {row["id"]: row["quality"] for row in states}
    rows = [{"id": a["id"], "priority": a["priority"], "quality": by[a["id"]]} for a in pack["artifacts"]]
    replayed = evaluate_gates(pack, rows)
    recorded = {name: assessment[name] for name in _SUMMARY_FIELDS}
    recorded_digest, replayed_digest = sha256_object(recorded), sha256_object(replayed)
    return {"schema": REPORT_SCHEMA, "status": "PASS" if recorded_digest == replayed_digest else "FAIL",
            "comparison_basis": "RFC8785-gate-summary", "case_id": case_id, "pack_id": pack["id"],
            "pack_sha256": value["pack_sha256"], "quality_states_sha256": sha256_object(states),
            "recorded_summary_sha256": recorded_digest, "replayed_summary_sha256": replayed_digest,
            "gate_results": [{key: gate[key] for key in ("id", "status", "missing", "insufficient_quality")} for gate in replayed["conclusion_gates"]],
            "recorded_quality_only": True, "raw_evidence_revalidated": False, "pack_approval_verified": False,
            "closure_authorized": False, "network_required": False,
            "interpretation": "Reproduced gate calculation over retained rules and recorded quality ratings; evidence quality and investigative conclusions require separate review."}


def load_replay_document(path: str | Path, *, limit: int) -> Any:
    path = Path(path)
    _require(not path.is_symlink() and path.is_file(), "a regular local JSON file is required")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "replay JSON file is empty, oversized, or not regular")
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, "replay JSON file exceeds its byte limit")
    try:
        return strict_json(raw)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProvenanceError("invalid Evidence Pack replay JSON") from exc
