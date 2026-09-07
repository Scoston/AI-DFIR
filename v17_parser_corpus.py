"""Repeatable synthetic hostile-input campaigns for fixed offline parser profiles.

This is bounded mutation testing, not a sandbox or exhaustive security proof.
No user-supplied parser, corpus, command, URL, or import path is accepted.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
import random
import socket
import subprocess
from unittest.mock import patch

import v17_azure_activity as azure
import v17_cloudtrail as cloudtrail
import v17_gcp_audit as audit
import v17_gcp_logging_context as logging_context
import v17_log_analytics as tables
import v17_log_analytics_context as query_context
import v17_log_analytics_lossless as lossless
from v17_azure_activity_selftest import synthetic_event as azure_event
from v17_cloudtrail_selftest import lookup_wrapper, synthetic_event as cloudtrail_event
from v17_gcp_audit_selftest import synthetic_entry as audit_entry
from v17_gcp_logging_capture_selftest import synthetic_context as logging_observation
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics_context_selftest import synthetic_context as query_observation
from v17_log_analytics_lossless_selftest import synthetic_numeric_response
from v17_log_analytics_selftest import synthetic_response as query_response

SCHEMA = "ai-dfir/parser-hostile-corpus/v1.7"
CORPUS_VERSION = "1"
DEFAULT_SEED = 17017
DEFAULT_MUTATIONS = 256
MAX_MUTATIONS = 2048
MAX_CASE_BYTES = 64 * 1024
MAX_FAILURE_DETAILS = 20


@dataclass(frozen=True)
class _Literal:
    text: str


def _encode(value):
    """Retain original numeric spelling in synthetic JSON mutations."""
    if isinstance(value, _Literal): return value.text
    if isinstance(value, list): return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=True) + ":" + _encode(item) for key, item in value.items()) + "}"
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _raw(value):
    return _encode(value).encode("ascii")


@dataclass(frozen=True)
class Profile:
    name: str
    module: object
    input_format: str
    seed: bytes
    response: bytes | None = None

    def normalize(self, raw):
        if self.response is None: return self.module.normalize(raw, input_format=self.input_format)
        return self.module.normalize(self.response, context_raw=raw, input_format=self.input_format)

    def compare(self, raw, output):
        if self.response is None: return self.module.compare_replay(raw, output, input_format=self.input_format)
        return self.module.compare_replay(self.response, output, context_raw=raw, input_format=self.input_format)


def profiles():
    """Twelve fixed native response/context profiles; factories use no I/O."""
    ct = cloudtrail_event(); ga = audit_entry(); az = azure_event()
    query = _raw(query_response(partial=True)); audit_raw = _raw({"entries": [ga], "nextPageToken": "SYNTHETIC-CONTINUATION"})
    return (
        Profile("cloudtrail-records", cloudtrail, "records", _raw({"Records": [ct]})),
        Profile("cloudtrail-lookup", cloudtrail, "lookup-events", _raw({"Events": [lookup_wrapper(ct)], "NextToken": "SYNTHETIC-CONTINUATION"})),
        Profile("gcp-audit-entries", audit, "entries", audit_raw),
        Profile("gcp-audit-array", audit, "array", _raw([ga])),
        Profile("azure-activity", azure, "activity-log", _raw({"value": [az], "nextLink": "https://example.invalid/continuation"})),
        Profile("azure-array", azure, "array", _raw([az])),
        Profile("log-analytics-tables", tables, "tables", query),
        Profile("log-analytics-resource", tables, "resource-tables", _raw(dict(query_response(partial=True), permissions={"observed": False}))),
        Profile("lossless-tables", lossless, "tables", synthetic_numeric_response(partial=True)),
        Profile("lossless-resource", lossless, "resource-tables", synthetic_numeric_response(partial=True, resource=True)),
        Profile("log-analytics-context", query_context, "workspace-post", _raw(query_observation(query)), query),
        Profile("gcp-logging-context", logging_context, "entries-list", _raw(logging_observation(audit_raw)), audit_raw),
    )


def _paths(value, prefix=()):
    yield prefix
    if isinstance(value, dict):
        for key, item in value.items(): yield from _paths(item, prefix + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value): yield from _paths(item, prefix + (index,))


def _get(value, path):
    for key in path: value = value[key]
    return value


def _replace(value, path, replacement, *, delete=False):
    if not path: return copy.deepcopy(replacement)
    result = copy.deepcopy(value); parent = _get(result, path[:-1])
    if delete: del parent[path[-1]]
    else: parent[path[-1]] = copy.deepcopy(replacement)
    return result


@dataclass(frozen=True)
class Case:
    category: str
    raw: bytes
    expectation: str | None = None

    def __post_init__(self):
        if not isinstance(self.raw, bytes) or len(self.raw) > MAX_CASE_BYTES or self.expectation not in (None, "ACCEPT", "REJECT"):
            raise ValueError("invalid or excessive synthetic corpus case")


def _options(seed, mutations):
    if type(seed) is not int or not 0 <= seed <= 4294967295:
        raise ValueError("corpus seed must be a 32-bit unsigned integer")
    if type(mutations) is not int or not 1 <= mutations <= MAX_MUTATIONS:
        raise ValueError("corpus mutation count is outside its bound")


def cases(profile, *, seed=DEFAULT_SEED, mutations=DEFAULT_MUTATIONS):
    _options(seed, mutations)
    raw = profile.seed
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CASE_BYTES:
        raise ValueError("invalid synthetic corpus seed")
    value = json.loads(raw.decode("utf-8"), parse_int=_Literal, parse_float=_Literal)
    paths = list(_paths(value))
    yield Case("seed", raw, "ACCEPT")
    yield Case("whitespace", b" \n" + raw + b"\t", "ACCEPT")
    for invalid in (b"", b"\x00" + raw, b"\xff" + raw, b"\xef\xbb\xbf" + raw,
                    raw + b" null", b"/*comment*/" + raw, raw + b"\x00"):
        yield Case("encoding", invalid, "REJECT")
    for cut in sorted({1, len(raw) // 4, len(raw) // 2, len(raw) - 1}):
        yield Case("truncation", raw[:cut], "REJECT")
    yield Case("depth", b"[" * 34 + raw + b"]" * 34, "REJECT")
    object_path = next(path for path in paths if isinstance(_get(value, path), dict) and _get(value, path))
    obj = _get(value, object_path); first_key = next(iter(obj))
    duplicate = _Literal("{" + json.dumps(first_key) + ":null," + _encode(obj)[1:])
    yield Case("duplicate-key", _raw(_replace(value, object_path, duplicate)), "REJECT")
    for hostile in ("\ud800", _Literal("1e" + "9" * 129), _Literal("9" * 129), _Literal("NaN"), _Literal("Infinity")):
        changed = dict(obj, _synthetic_hostile=hostile)
        yield Case("invalid-leaf", _raw(_replace(value, object_path, changed)), "REJECT")
    if profile.name == "cloudtrail-lookup":
        embedded = value["Events"][0]["CloudTrailEvent"]
        for hostile in ("null", "[]", "{}", embedded[:-1], '{"eventID":null,' + embedded[1:],
                        "[" * 34 + embedded + "]" * 34):
            changed = _replace(value, ("Events", 0, "CloudTrailEvent"), hostile)
            yield Case("embedded-json", _raw(changed), "REJECT")
    values = (None, True, False, 0, 1, -1, "", "SYNTHETIC-CORPUS", "\x00", "\udfff",
              [], {}, [None], {"unexpected": True}, _Literal("1e309"), _Literal("-0.0"))
    # Each profile has a stable independent stream, unaffected by profile order.
    stream_seed = int.from_bytes(hashlib.sha256(f"{seed}:{profile.name}".encode()).digest(), "big")
    randomizer = random.Random(stream_seed)
    for index in range(mutations):
        path = paths[randomizer.randrange(len(paths))]
        delete = bool(path) and index % 4 == 0
        replacement = values[randomizer.randrange(len(values))]
        changed = _replace(value, path, replacement, delete=delete)
        encoded = _raw(changed)
        if len(encoded) > MAX_CASE_BYTES: raise ValueError("synthetic mutation exceeded its bound")
        yield Case("delete" if delete else "structure", encoded)


def _outcome(profile, raw):
    try:
        value = profile.normalize(raw)
    except ValueError:
        return "REJECT", None, None
    except Exception as exc:
        return "CRASH", None, type(exc).__name__
    try:
        if not isinstance(value, dict): raise AssertionError("projection object required")
        encoded = canonical_json_bytes(value)
        if len(encoded) > profile.module.MAX_OUTPUT_BYTES: raise AssertionError("projection output bound")
        expected_raw = profile.response if profile.response is not None else raw
        if value.get("source_sha256") != sha256_bytes(expected_raw): raise AssertionError("source digest binding")
        if profile.response is not None and value.get("context_sha256") != sha256_bytes(raw): raise AssertionError("context digest binding")
        if value.get("source_authenticity_verified") is not False: raise AssertionError("source authority promotion")
        if value.get("network_required") is not False: raise AssertionError("network requirement promotion")
        if value.get("collection_complete") is not False and value.get("collection_complete") is not None:
            raise AssertionError("collection completeness promotion")
        for field in ("request_scope_verified", "query_execution_verified", "query_reexecuted", "permissions_verified", "pagination_chain_verified"):
            if field in value and value[field] is not False: raise AssertionError("unverified operational claim promoted")
        if profile.compare(raw, encoded).get("status") != "PASS": raise AssertionError("valid replay mismatch")
        corrupted = dict(value, source_sha256="0" * 64)
        if profile.compare(raw, canonical_json_bytes(corrupted)).get("status") != "FAIL": raise AssertionError("corrupted replay accepted")
        return "ACCEPT", sha256_bytes(encoded), None
    except Exception as exc:
        return "INVARIANT_FAILURE", None, type(exc).__name__


def run_campaign(*, seed=DEFAULT_SEED, mutations=DEFAULT_MUTATIONS, selected=None):
    _options(seed, mutations)
    available = profiles(); names = [item.name for item in available]
    if selected is not None:
        if (not isinstance(selected, (list, tuple)) or not selected or len(selected) > len(names)
                or not all(isinstance(item, str) and item in names for item in selected) or len(set(selected)) != len(selected)):
            raise ValueError("unsupported or duplicate fixed corpus profile")
        available = tuple(item for item in available if item.name in selected)
    failures = []; failure_count = 0; rows = []; transcript = hashlib.sha256(); corpus = hashlib.sha256()
    with ExitStack() as guards:
        for target, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
                             (socket, "create_connection"), (socket, "getaddrinfo"), (subprocess, "Popen"), (os, "system")):
            guards.enter_context(patch.object(target, name, side_effect=AssertionError("corpus external action blocked")))
        for profile in available:
            counts = {"ACCEPT": 0, "REJECT": 0, "CRASH": 0, "INVARIANT_FAILURE": 0}; categories = {}; inputs = set()
            for ordinal, case in enumerate(cases(profile, seed=seed, mutations=mutations)):
                first = _outcome(profile, case.raw); second = _outcome(profile, case.raw)
                status, output_sha, error_type = first
                counts[status] += 1; categories[case.category] = categories.get(case.category, 0) + 1
                ident = {"profile": profile.name, "ordinal": ordinal, "category": case.category,
                         "input_sha256": sha256_bytes(case.raw), "expectation": case.expectation}
                inputs.add(ident["input_sha256"])
                corpus.update(canonical_json_bytes(ident) + b"\n")
                row = dict(ident, status=status, output_sha256=output_sha, error_type=error_type)
                transcript.update(canonical_json_bytes(row) + b"\n")
                reason = "NONDETERMINISTIC" if first != second else "EXPECTED_RESULT_MISMATCH" if case.expectation is not None and status != case.expectation else status if status not in {"ACCEPT", "REJECT"} else None
                if reason is not None:
                    failure_count += 1
                    if len(failures) < MAX_FAILURE_DETAILS: failures.append(dict(row, reason=reason))
            rows.append({"profile": profile.name, "seed_sha256": sha256_bytes(profile.seed),
                         "cases": sum(counts.values()), "unique_inputs": len(inputs), "outcomes": counts, "categories": categories})
    return {"schema": SCHEMA, "corpus_version": CORPUS_VERSION, "status": "FAIL" if failure_count else "PASS",
            "seed": seed, "mutations_per_profile": mutations, "profile_count": len(rows),
            "case_count": sum(row["cases"] for row in rows), "profiles": rows,
            "unique_profile_inputs": sum(row["unique_inputs"] for row in rows),
            "corpus_sha256": corpus.hexdigest(), "outcome_sha256": transcript.hexdigest(),
            "failure_count": failure_count, "failures": failures, "failure_details_truncated": failure_count > len(failures),
            "parser_invocations_repeated": True, "network_blocked": True, "process_creation_blocked": True, "network_performed": False,
            "user_corpus_loaded": False, "coverage_guided": False, "exhaustive": False,
            "interpretation": "Bounded deterministic synthetic mutation testing of fixed provider parsers and retained contexts; no exhaustive parser security, hostile-file isolation, live acquisition, or production qualification is established."}
