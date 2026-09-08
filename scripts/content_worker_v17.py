#!/usr/bin/env python3
"""Internal fixed text/PDF worker; never accept paths or arbitrary commands."""
import json
import os
from pathlib import Path
import sys


def pdf_projection(raw):
    import pymupdf
    from evil_font_forensics import analyze_font_bytes
    from v17_content_intake import FONT_BYTES, require
    from v17_integrity import sha256_bytes
    pymupdf.TOOLS.mupdf_display_errors(False)
    pymupdf.TOOLS.mupdf_display_warnings(False)
    fonts, findings, chunks = [], [], []
    text_chars = font_bytes = font_references = 0
    with pymupdf.open(stream=raw, filetype="pdf") as document:
        require(document.is_pdf and not document.needs_pass and type(document.page_count) is int
                and 0 <= document.page_count <= 64)
        require(not document.is_repaired)
        pages = document.page_count
        seen = set()
        for number in range(pages):
            page = document.load_page(number)
            text = page.get_text("text")
            text_chars += len(text); require(text_chars <= 256 * 1024)
            chunks.append(text)
            references = page.get_fonts(full=True)
            font_references += len(references); require(font_references <= 4096)
            for reference in references:
                xref = reference[0]
                if xref in seen: continue
                require(len(seen) < 32); seen.add(xref)
                item = {"xref": xref}
                try:
                    require(type(xref) is int and xref > 0)
                    name, ext, kind, data = document.extract_font(xref)
                    require(type(data) is bytes and 12 <= len(data) <= FONT_BYTES
                            and data[:4] in {b"\x00\x01\x00\x00", b"OTTO"})
                    require(font_bytes + len(data) <= 8 * 1024**2); font_bytes += len(data)
                    result = analyze_font_bytes(data, "PDF embedded font")
                    require(result.get("available") is True and not result.get("error"))
                    item.update(name=name, ext=ext, type=kind, analysis=result)
                    findings.extend({**f, "font_xref": xref} for f in result["findings"])
                except Exception:
                    item["analysis_available"] = False
                    findings.append({"type": "pdf_font_analysis_incomplete", "severity": "high", "font_xref": xref})
                fonts.append(item)
    text = "".join(chunks)
    return {"pages": pages, "extracted_text_chars": text_chars,
            "extracted_text_sha256": sha256_bytes(text.encode()) if text else None,
            "embedded_fonts": fonts, "findings": findings}


def main():
    import resource
    if len(sys.argv) != 2 or sys.argv[1] not in {"plain", "markup", "pdf"}: return 1
    mode = sys.argv[1]
    cpu, memory = (8, 512) if mode == "pdf" else (3, 256)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (memory * 1024**2, memory * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077); sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from contextlib import ExitStack
    import socket
    import subprocess
    from unittest.mock import patch
    from v17_content_intake import MODES, OUTPUT_BYTES, SCHEMA, require
    from v17_integrity import canonical_json_bytes, sha256_bytes
    raw = sys.stdin.buffer.read(MODES[mode][0] + 1); require(len(raw) <= MODES[mode][0])
    with ExitStack() as guards:
        for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
                            (socket, "create_connection"), (socket, "getaddrinfo"), (subprocess, "Popen"), (os, "system")):
            guards.enter_context(patch.object(owner, name, side_effect=RuntimeError("content worker external action blocked")))
        if mode == "pdf":
            require(raw.startswith(b"%PDF-")); analyses = {"pdf": pdf_projection(raw)}
        else:
            from unicode_forensics import analyze as unicode_analyze
            from terminal_render_forensics import analyze as terminal_analyze
            from markup_representation_forensics import analyze as markup_analyze
            text = raw.decode("utf-8", errors="strict")
            analyses = {"unicode": unicode_analyze(text), "terminal": terminal_analyze(text)}
            if mode == "markup": analyses["markup"] = markup_analyze(text)
    report = {"schema": SCHEMA, "available": True, "mode": mode, "source_sha256": sha256_bytes(raw),
              "source_size_bytes": len(raw), "analyses": analyses, "source_authenticity_verified": False,
              "independent_rendering_verified": False, "collection_complete": None, "network_required": False}
    require(len(canonical_json_bytes(report)) <= OUTPUT_BYTES)
    encoded = json.dumps(report, allow_nan=False, ensure_ascii=True).encode()
    require(len(encoded) <= OUTPUT_BYTES); sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (Exception, KeyboardInterrupt): raise SystemExit(1)
