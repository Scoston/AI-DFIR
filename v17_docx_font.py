"""Fixed child-process boundary for selected DOCX TrueType/OpenType geometry."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from v17_integrity import sha256_bytes

MAX_INPUT_BYTES = 4 * 1024**2
MAX_OUTPUT_BYTES = 256 * 1024
TIMEOUT_SECONDS = 5
WORKER = Path(__file__).resolve().parent / "scripts/docx_font_worker_v17.py"


def analyze(data):
    unknown = {"available": False, "error": "embedded font analysis unavailable, unsupported, or resource-limited", "findings": []}
    if (type(data) is not bytes or not 12 <= len(data) <= MAX_INPUT_BYTES
            or data[:4] not in {b"\x00\x01\x00\x00", b"OTTO"} or sys.platform != "linux"):
        return unknown
    try:
        process = subprocess.Popen([sys.executable, str(WORKER)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            output, _ = process.communicate(data, timeout=TIMEOUT_SECONDS)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode != 0 or len(output) > MAX_OUTPUT_BYTES:
            return unknown
        report = json.loads(output)
        if (not isinstance(report, dict) or report.get("sha256") != sha256_bytes(data)
                or report.get("error") or report.get("available") is not True
                or not isinstance(report.get("findings"), list)
                or not all(isinstance(row, dict) for row in report["findings"])):
            return unknown
        return report
    except Exception:
        return unknown
