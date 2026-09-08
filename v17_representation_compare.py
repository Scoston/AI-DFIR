"""Bounded two-source text comparison; supplied visible text is not a renderer."""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys

from v17_content_intake import read_snapshot, output_report, _object, _constant, require
from v17_integrity import canonical_json_bytes, sha256_bytes

SCHEMA = "ai-dfir/bounded-representation-comparison/v1.7"
RESULT_SCHEMA = "ai-dfir/representation-differential/v1.2"
TEXT_BYTES = 16 * 1024
INPUT_BYTES = 48 * 1024
OUTPUT_BYTES = 64 * 1024
WALL_SECONDS = 5
WORKER = Path(__file__).resolve().parent / "scripts/representation_compare_worker_v17.py"
FALSE_FLAGS = ("independent_rendering_verified", "source_authenticity_verified", "network_required")


def inputs(machine, visible):
    require(all(type(raw) is bytes and len(raw) <= TEXT_BYTES for raw in (machine, visible)))
    texts = tuple(raw.decode("utf-8", errors="strict") for raw in (machine, visible))
    return texts


def request(machine, visible):
    inputs(machine, visible)
    raw = canonical_json_bytes({"schema": SCHEMA, "machine": base64.b64encode(machine).decode(),
                                "visible": base64.b64encode(visible).decode()})
    require(len(raw) <= INPUT_BYTES)
    return raw


def decode_request(raw):
    require(type(raw) is bytes and len(raw) <= INPUT_BYTES)
    obj = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    require(isinstance(obj, dict) and set(obj) == {"schema", "machine", "visible"} and obj["schema"] == SCHEMA)
    result = []
    for name in ("machine", "visible"):
        text = obj[name]; require(isinstance(text, str) and len(text) <= 21848)
        data = base64.b64decode(text, validate=True)
        require(base64.b64encode(data).decode() == text); result.append(data)
    inputs(*result)
    return tuple(result)


def intake(machine, visible, available):
    return {"schema": SCHEMA, "analysis_available": available,
            "machine_source_sha256": sha256_bytes(machine), "visible_source_sha256": sha256_bytes(visible),
            "machine_size_bytes": len(machine), "visible_size_bytes": len(visible),
            **{key: False for key in FALSE_FLAGS}, "collection_complete": None}


def score(value):
    return type(value) in (int, float) and 0 <= value <= 1 and math.isfinite(value)


def validate(report, machine, visible):
    texts = inputs(machine, visible)
    keys = {"schema", "machine_text_sha256", "visible_text_sha256", "machine_source", "visible_source",
            "machine_chars", "visible_chars", "token_similarity", "character_similarity", "findings", "rule", "intake"}
    require(isinstance(report, dict) and set(report) == keys and report["schema"] == RESULT_SCHEMA)
    expected = intake(machine, visible, True)
    actual = report["intake"]
    require(isinstance(actual, dict) and set(actual) == set(expected) and actual == expected
            and actual["analysis_available"] is True and actual["collection_complete"] is None
            and all(actual[key] is False for key in FALSE_FLAGS)
            and all(type(actual[key]) is int for key in ("machine_size_bytes", "visible_size_bytes")))
    for name, raw, text in zip(("machine", "visible"), (machine, visible), texts, strict=True):
        require(report[name + "_source"] is None and report[name + "_text_sha256"] == sha256_bytes(raw)
                and type(report[name + "_chars"]) is int and report[name + "_chars"] == len(text))
    require(score(report["token_similarity"]) and score(report["character_similarity"])
            and isinstance(report["rule"], str) and 0 < len(report["rule"]) <= 256)
    rows = report["findings"]; require(isinstance(rows, list) and len(rows) <= 1)
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"type", "severity", "token_similarity", "character_similarity", "divergence"}
                and row["type"] == "human_machine_representation_divergence"
                and isinstance(row["severity"], str) and row["severity"] in {"critical", "high"}
                and score(row["divergence"])
                and all(score(row[key]) and row[key] == report[key] for key in ("token_similarity", "character_similarity")))
    require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
    return report


def compare(machine, visible):
    unknown = {"schema": RESULT_SCHEMA, "findings": [{"type": "representation_comparison_incomplete", "severity": "high"}],
               "intake": {"schema": SCHEMA, "analysis_available": False,
                          **{key: False for key in FALSE_FLAGS}, "collection_complete": None}}
    try:
        require(all(type(raw) is bytes and len(raw) <= TEXT_BYTES for raw in (machine, visible)))
        unknown["intake"] = intake(machine, visible, False)
        raw = request(machine, visible)
        if sys.platform != "linux": return unknown
        process = subprocess.Popen([sys.executable, str(WORKER)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            output, _ = process.communicate(raw, timeout=WALL_SECONDS)
        except BaseException:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.communicate(); raise
        require(process.returncode == 0 and len(output) <= OUTPUT_BYTES)
        return validate(json.loads(output, object_pairs_hook=_object, parse_constant=_constant), machine, visible)
    except Exception:
        return unknown


def compare_files(machine, visible, *, source_machine=None, source_visible=None):
    labels = (str(machine) if source_machine is None else source_machine,
              str(visible) if source_visible is None else source_visible)
    require(all(isinstance(label, str) and len(label) <= 4096 for label in labels))
    report = compare(read_snapshot(machine, TEXT_BYTES), read_snapshot(visible, TEXT_BYTES))
    report.update(machine_source=labels[0], visible_source=labels[1])
    require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--machine", required=True); parser.add_argument("--visible", required=True)
    parser.add_argument("--machine-source"); parser.add_argument("--visible-source"); parser.add_argument("--out")
    args = parser.parse_args()
    try:
        report = compare_files(args.machine, args.visible, source_machine=args.machine_source, source_visible=args.visible_source)
        output_report(report, args.out, limit=OUTPUT_BYTES)
        return 0 if report["intake"]["analysis_available"] else 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps({"status": "FAIL", "error": "invalid, excessive comparison input or unavailable output"}))
        return 1
