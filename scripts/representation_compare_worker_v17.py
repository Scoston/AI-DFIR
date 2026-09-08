#!/usr/bin/env python3
"""Internal fixed two-text worker with process limits and no evidence paths."""
import json
import os
from pathlib import Path
import sys


def main():
    import resource
    if len(sys.argv) != 1: return 1
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077); sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from contextlib import ExitStack
    import socket
    import subprocess
    from unittest.mock import patch
    from representation_differential import analyze
    from v17_representation_compare import INPUT_BYTES, OUTPUT_BYTES, decode_request, inputs, intake, validate
    from v17_content_intake import require
    machine, visible = decode_request(sys.stdin.buffer.read(INPUT_BYTES + 1))
    with ExitStack() as guards:
        for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket.socket, "sendto"),
                            (socket, "create_connection"), (socket, "getaddrinfo"), (subprocess, "Popen"), (os, "system")):
            guards.enter_context(patch.object(owner, name, side_effect=RuntimeError("comparison worker external action blocked")))
        report = analyze(*inputs(machine, visible))
    report["intake"] = intake(machine, visible, True)
    validate(report, machine, visible)
    output = json.dumps(report, ensure_ascii=True, allow_nan=False).encode()
    require(len(output) <= OUTPUT_BYTES); sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (Exception, KeyboardInterrupt): raise SystemExit(1)
