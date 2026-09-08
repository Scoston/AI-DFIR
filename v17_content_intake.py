"""Fixed resource-limited text/PDF workers and bounded file/report boundaries."""
from __future__ import annotations

import json
import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from v17_docx_font import analyze as analyze_font
from v17_html_intake import Resources
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

SCHEMA = "ai-dfir/bounded-content-worker/v1.7"
TEXT_BYTES = 256 * 1024
FONT_BYTES = 4 * 1024**2
PDF_BYTES = 8 * 1024**2
OUTPUT_BYTES = 2 * 1024**2
GATE_OUTPUT_BYTES = 8 * 1024**2
MODES = {"plain": (TEXT_BYTES, 3, 256, 5), "markup": (TEXT_BYTES, 3, 256, 5), "pdf": (PDF_BYTES, 8, 512, 12)}
WORKER = Path(__file__).resolve().parent / "scripts/content_worker_v17.py"
FALSE_FLAGS = ("source_authenticity_verified", "independent_rendering_verified", "network_required")


def require(condition):
    if not condition: raise ProvenanceError("invalid, unsupported, or excessive content intake")


def read_snapshot(path, limit):
    p = Path(path).absolute(); resources = Resources(p.parent)
    try: return resources.read((p.name,), limit, "content")
    finally: resources.close()


def output_report(report, path=None, *, limit=OUTPUT_BYTES):
    require(len(canonical_json_bytes(report)) <= limit)
    raw = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()
    require(len(raw) <= limit)
    if path is None:
        sys.stdout.buffer.write(raw)
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result); result[key] = value
    return result


def _constant(value):
    raise ValueError("non-finite worker response")


def valid_findings(rows):
    return (isinstance(rows, list) and all(isinstance(r, dict) and isinstance(r.get("type"), str)
            and r.get("severity") in {"critical", "high", "medium", "low"} for r in rows))


def run_worker(raw, *, mode):
    selected_mode = mode if type(mode) is str and mode in MODES else "unsupported"
    unknown = {"schema": SCHEMA, "available": False, "mode": selected_mode,
               "error": "content analysis unavailable, unsupported, invalid, or resource-limited"}
    if selected_mode == "unsupported" or type(raw) is not bytes or len(raw) > MODES[mode][0] or sys.platform != "linux":
        return unknown
    if mode == "pdf" and not raw.startswith(b"%PDF-"): return unknown
    try:
        process = subprocess.Popen([sys.executable, str(WORKER), mode], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            output, _ = process.communicate(raw, timeout=MODES[mode][3])
        except BaseException:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.communicate(); raise
        require(process.returncode == 0 and len(output) <= OUTPUT_BYTES)
        report = json.loads(output, object_pairs_hook=_object, parse_constant=_constant)
        require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("mode") == mode
                and report.get("available") is True and not report.get("error")
                and report.get("source_sha256") == sha256_bytes(raw)
                and type(report.get("source_size_bytes")) is int and report["source_size_bytes"] == len(raw)
                and "collection_complete" in report and report["collection_complete"] is None
                and all(report.get(k) is False for k in FALSE_FLAGS))
        analyses = report.get("analyses")
        expected = {"pdf"} if mode == "pdf" else ({"unicode", "terminal", "markup"} if mode == "markup" else {"unicode", "terminal"})
        require(isinstance(analyses, dict) and set(analyses) == expected
                and all(isinstance(v, dict) and valid_findings(v.get("findings")) for v in analyses.values()))
        if mode == "pdf":
            pdf = analyses["pdf"]
            require(type(pdf.get("pages")) is int and 0 <= pdf["pages"] <= 64
                    and type(pdf.get("extracted_text_chars")) is int and 0 <= pdf["extracted_text_chars"] <= TEXT_BYTES
                    and isinstance(pdf.get("embedded_fonts"), list) and len(pdf["embedded_fonts"]) <= 32
                    and all(isinstance(f, dict) and type(f.get("xref")) is int and f["xref"] >= 0 for f in pdf["embedded_fonts"]))
            digest = pdf.get("extracted_text_sha256")
            require((pdf["extracted_text_chars"] == 0 and digest is None)
                    or (pdf["extracted_text_chars"] > 0 and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)))
        else:
            schemas = {"unicode": "ai-dfir/unicode-representation-analysis/v1.2",
                       "terminal": "ai-dfir/terminal-render-analysis/v1.2", "markup": "ai-dfir/markup-representation-analysis/v1.2"}
            require(all(analyses[k].get("schema") == schemas[k] for k in expected))
            require(type(analyses["unicode"].get("length")) is int
                    and analyses["unicode"]["length"] == len(raw.decode("utf-8", errors="strict")))
            if mode == "markup": require(analyses["markup"].get("source_sha256") == sha256_bytes(raw))
        require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
        return report
    except Exception:
        return unknown


def font_file(path):
    raw = read_snapshot(path, FONT_BYTES)
    analysis = analyze_font(raw)
    findings = list(analysis.get("findings", []))
    if analysis.get("available") is not True or analysis.get("error"):
        findings.append({"type": "font_analysis_incomplete", "severity": "high"})
    report = {"schema": "ai-dfir/bounded-font-file/v1.7", "path": str(Path(path).absolute()),
              "source_sha256": sha256_bytes(raw), "source_size_bytes": len(raw), "analysis": analysis,
              "findings": findings, "source_authenticity_verified": False,
              "independent_rendering_verified": False, "collection_complete": None, "network_required": False}
    require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
    return report


def text_cli(domain):
    """Shared safe file/worker/output path for the three specialist text CLIs."""
    require(domain in {"unicode", "terminal", "markup"})
    parser = argparse.ArgumentParser(); parser.add_argument("path"); parser.add_argument("--out")
    args = parser.parse_args()
    try:
        raw = read_snapshot(args.path, TEXT_BYTES)
        worker = run_worker(raw, mode="markup" if domain == "markup" else "plain")
        available = worker.get("available") is True
        report = worker["analyses"][domain] if available else {
            "schema": SCHEMA, "findings": [{"type": "text_analysis_incomplete", "severity": "high"}]}
        report["intake"] = {"source_sha256": sha256_bytes(raw), "source_size_bytes": len(raw),
                            "analysis_available": available, "source_authenticity_verified": False,
                            "independent_rendering_verified": False, "collection_complete": None, "network_required": False}
        output_report(report, args.out)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        print(json.dumps({"status": "FAIL", "error": "invalid, unsupported, excessive text or unavailable output"}))
        raise SystemExit(1)
    raise SystemExit(0 if available else 1)


def pdf_file(path):
    raw = read_snapshot(path, PDF_BYTES); require(raw.startswith(b"%PDF-"))
    findings = []
    if re.search(rb"(?<!\d)3\s+Tr\b", raw):
        findings.append({"type": "pdf_invisible_text_render_mode_3", "severity": "critical"})
    markers = len(re.findall(rb"/Subtype\s*/Image\b", raw))
    worker = run_worker(raw, mode="pdf")
    projection = worker.get("analyses", {}).get("pdf", {}) if worker.get("available") is True else {}
    findings.extend(projection.get("findings", []))
    if worker.get("available") is not True:
        findings.append({"type": "pdf_analysis_incomplete", "severity": "high"})
    pages = projection.get("pages")
    if pages and markers >= pages and projection.get("extracted_text_chars", 0) >= 50:
        findings.append({"type": "pdf_image_dominant_with_machine_text_layer", "severity": "high",
                         "pages": pages, "image_markers": markers, "extracted_text_chars": projection["extracted_text_chars"]})
    report = {"schema": "ai-dfir/evil-font-pdf-analysis/v1.2", "path": str(Path(path).absolute()),
              "pdf_sha256": sha256_bytes(raw), "source_size_bytes": len(raw), "image_markers": markers,
              "extracted_text_sha256": projection.get("extracted_text_sha256"),
              "embedded_fonts": projection.get("embedded_fonts", []), "pages": pages, "findings": findings,
              "analysis_available": worker.get("available") is True, "analysis_profile": SCHEMA,
              "source_authenticity_verified": False, "independent_rendering_verified": False,
              "collection_complete": None, "network_required": False,
              "note": "Raw marker matches are static leads, not complete PDF interpretation or independent rendering."}
    require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
    return report
