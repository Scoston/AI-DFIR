#!/usr/bin/env python3
"""Internal fixed-input font worker; resource controls are not an OS sandbox."""
import json
import os
from pathlib import Path
import sys


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from contextlib import ExitStack
    import socket
    import subprocess
    from unittest.mock import patch
    from evil_font_forensics import analyze_font_bytes
    from v17_docx_font import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not 12 <= len(data) <= MAX_INPUT_BYTES or data[:4] not in {b"\x00\x01\x00\x00", b"OTTO"}:
        return 1
    with ExitStack() as guards:
        for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
                            (socket, "getaddrinfo"), (socket, "create_connection"), (subprocess, "Popen"), (os, "system")):
            guards.enter_context(patch.object(owner, name, side_effect=RuntimeError("font worker external action blocked")))
        report = analyze_font_bytes(data, "embedded font")
    if report.get("error") or report.get("available") is not True:
        return 1
    encoded = json.dumps(report, allow_nan=False, ensure_ascii=True).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        return 1
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        raise SystemExit(1)
