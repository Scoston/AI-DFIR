"""Fixed synthetic coverage-fuzz targets; no optional engine import is needed."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import os
import socket
import subprocess
import tarfile
import zipfile
from unittest.mock import patch

import v17_archive_intake_selftest as archives
import v17_docx_intake as docx
import v17_docx_intake_selftest as docx_seeds
import v17_html_intake as html
import v17_parser_corpus as providers
from v17_integrity import canonical_json_bytes
from v17_provenance import ProvenanceError

SCHEMA = "ai-dfir/coverage-fuzz-targets/v1.7"
MAX_INPUT_BYTES = 16 * 1024 + 1  # Includes the one-byte, versioned selector.
PROVIDERS = providers.profiles()
ARCHIVE_FORMATS = ("zip", "tar", "tar-gzip", "tar-bzip2", "tar-xz")
PROFILE_NAMES = tuple(p.name for p in PROVIDERS) + tuple("archive-" + f for f in ARCHIVE_FORMATS) + ("docx-selected-parts", "html-static", "css-font-face")
INSTRUMENTED_MODULES = (
    "v17_fuzz_targets", "v17_parser_corpus", "v17_archive_intake_selftest",
    "v17_archive_intake", "v17_cloudtrail", "v17_gcp_audit", "v17_azure_activity",
    "v17_log_analytics", "v17_log_analytics_lossless", "v17_numeric_json",
    "v17_log_analytics_context", "v17_gcp_logging_context", "v17_reconstruction",
    "v17_provenance", "v17_integrity",
    "v17_docx_intake", "v17_docx_intake_selftest",
    "v17_html_intake",
)


def seed_inputs():
    """Build before installing member-I/O guards: ZIP fixture writers use open."""
    retained = archives.seeds()
    payloads = tuple(p.seed for p in PROVIDERS) + tuple(retained[f] for f in ARCHIVE_FORMATS)
    payloads += (docx_seeds.package({
        "word/document.xml": docx_seeds.DOCUMENT, "word/fontTable.xml": docx_seeds.font_table(),
        "word/_rels/fontTable.xml.rels": docx_seeds.relationships(),
        "word/fonts/synthetic.ttf": b"synthetic opaque font",
    }, compression=zipfile.ZIP_STORED),)
    payloads += (b'<html><body><span style="font-family: \'Demo 41\'">sample</span></body></html>',
                 b'@font-face{font-family:Synthetic;src:url("fonts/demo.ttf")}')
    return tuple(bytes([index]) + raw for index, raw in enumerate(payloads))


@contextmanager
def blocked_actions():
    """Tripwires for these Python APIs; not an OS or native-code sandbox."""
    with ExitStack() as guards:
        for owner, name in (
            (socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
            (socket, "create_connection"), (socket, "getaddrinfo"), (subprocess, "Popen"),
            (os, "system"), (zipfile.ZipFile, "open"), (zipfile.ZipFile, "extract"),
            (zipfile.ZipFile, "extractall"), (tarfile.TarFile, "extractfile"),
            (tarfile.TarFile, "extract"), (tarfile.TarFile, "extractall"),
        ):
            guards.enter_context(patch.object(owner, name, side_effect=AssertionError("fuzz target external action blocked")))
        yield


def exercise(data):
    """Selector 0..19 + raw bytes. Unknown selectors are ignored, never imported."""
    if not __debug__:
        raise RuntimeError("fuzz assertions must be enabled")
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        raise ValueError("invalid or excessive fuzz input")
    if not data or data[0] >= len(PROFILE_NAMES):
        return "IGNORED", None
    selector, raw = data[0], data[1:]

    def once():
        if selector >= len(PROVIDERS) + len(ARCHIVE_FORMATS) + 1:
            # Empty HTML/CSS is valid for intake but not a useful fuzz seed.
            if not raw:
                return "REJECT", None
            try:
                report = html.inspect_static(raw, input_format=("html", "css")[selector - 18])
            except ProvenanceError:
                return "REJECT", None
            assert report["source_sha256"] == hashlib.sha256(raw).hexdigest()
            assert report["collection_complete"] is None
            for flag in ("filesystem_resources_loaded", "font_geometry_verified", "source_authenticity_verified",
                         "complete_visible_rendering_verified", "network_required"):
                assert report[flag] is False
            encoded = canonical_json_bytes(report)
            assert len(encoded) <= html.MAX_OUTPUT_BYTES
            return "ACCEPT", hashlib.sha256(encoded).hexdigest()
        if selector == len(PROVIDERS) + len(ARCHIVE_FORMATS):
            try:
                parts = docx.load_docx(raw)
            except ProvenanceError:
                return "REJECT", None
            report = parts.intake
            assert report["source_sha256"] == hashlib.sha256(raw).hexdigest()
            assert report["selected_part_size_crc_checked"] is True and report["collection_complete"] is None
            assert len(report["selected_parts"]) == len(parts)
            for row in report["selected_parts"]:
                assert row["sha256"] == hashlib.sha256(parts[row["name"]]).hexdigest()
                assert row["size_bytes"] == len(parts[row["name"]])
            for flag in ("all_member_payloads_verified", "external_resources_loaded", "filesystem_extraction",
                         "source_authenticity_verified", "complete_visible_rendering_verified", "network_required"):
                assert report[flag] is False
            return "ACCEPT", hashlib.sha256(canonical_json_bytes(report)).hexdigest()
        if selector < len(PROVIDERS):
            status, digest, error = providers._outcome(PROVIDERS[selector], raw)
            if status not in {"ACCEPT", "REJECT"} or error is not None:
                raise AssertionError("provider fuzz invariant or crash: " + str(status))
            return status, digest
        return archives._outcome(raw, ARCHIVE_FORMATS[selector - len(PROVIDERS)])

    first = once()
    if first != once():
        raise AssertionError("nondeterministic fuzz outcome")
    return first


def preflight():
    retained = seed_inputs()
    rows = []
    with blocked_actions():
        for index, (name, raw) in enumerate(zip(PROFILE_NAMES, retained, strict=True)):
            accepted = exercise(raw)
            rejected = exercise(bytes([index]))
            if accepted[0] != "ACCEPT" or rejected != ("REJECT", None):
                raise AssertionError("fuzz seed expectation mismatch")
            rows.append({"profile": name, "selector": index, "seed_sha256": hashlib.sha256(raw).hexdigest(),
                         "output_sha256": accepted[1]})
    return {"schema": SCHEMA, "status": "PASS", "profiles": len(rows), "cases": 2 * len(rows),
            "seed_manifest_sha256": hashlib.sha256(canonical_json_bytes(rows)).hexdigest(),
            "rows": rows, "coverage_guided": False, "network_required": False,
            "native_sanitizers": False, "os_sandbox": False, "exhaustive": False}
