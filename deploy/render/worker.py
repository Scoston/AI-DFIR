#!/usr/bin/env python3
"""Fixed PDF raster/OCR worker. Refuse to render without the container controls."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import socket
import struct
import subprocess
import sys
import tempfile

SCHEMA = "ai-dfir/isolated-pdf-render/v1.7"
PROFILE = "pdf-raster-ocr-v1.7"
SOURCE_BYTES = 8 * 1024**2
PNG_BYTES = 5 * 1024**2
WIRE_BYTES = 32 * 1024**2
TEXT_BYTES = 16 * 1024
MAX_PAGES = 4
MAX_SIDE = 2048
MEMORY_BYTES = 512 * 1024**2
TMPFS_BYTES = 64 * 1024**2
STAGE = "isolation"


def require(condition):
    if not condition: raise ValueError("unsupported, excessive, failed, or unisolated PDF rendering")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_read(path, limit):
    with open(path, "rb") as stream: raw = stream.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def isolation():
    require(sys.platform == "linux" and os.getuid() == 65532 and os.getgid() == 65532)
    status = bounded_read("/proc/self/status", 16384).decode("ascii")
    values = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    require(values["NoNewPrivs"].strip() == "1" and values["Seccomp"].strip() == "2"
            and int(values["CapEff"].strip(), 16) == 0 and int(values["CapBnd"].strip(), 16) == 0)
    require(sorted(os.listdir("/sys/class/net")) == ["lo"])
    with socket.socket() as probe:
        probe.settimeout(0.2)
        require(probe.connect_ex(("192.0.2.1", 443)) != 0)
    root = Path("/sys/fs/cgroup")
    read = lambda name: bounded_read(root / name, 128).decode().strip()
    require(read("memory.max") == str(MEMORY_BYTES) and read("memory.swap.max") == "0"
            and read("pids.max") == "64")
    quota, period = read("cpu.max").split(); require(int(quota) == int(period) and int(period) > 0)
    mounts = bounded_read("/proc/self/mountinfo", 65536).decode().splitlines()
    root_rows = [line.split() for line in mounts if line.split()[4] == "/"]
    require(len(root_rows) == 1 and "ro" in root_rows[0][5].split(","))
    tmp_rows = [line.split() for line in mounts if line.split()[4] == "/tmp"]
    require(len(tmp_rows) == 1 and {"rw", "noexec", "nosuid", "nodev"} <= set(tmp_rows[0][5].split(",")))
    stats = os.statvfs("/tmp"); require(stats.f_frsize * stats.f_blocks <= TMPFS_BYTES)
    for kind, expected in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, SOURCE_BYTES),
                           (resource.RLIMIT_CPU, 30), (resource.RLIMIT_NOFILE, 64)):
        require(resource.getrlimit(kind) == (expected, expected))
    return {"nonroot": True, "capabilities_dropped": True, "no_new_privileges": True, "seccomp_filter": True,
            "network_none": True, "root_read_only": True, "tmpfs_bounded_noexec": True,
            "memory_swap_cpu_pids_limits": True, "process_limits": True}


def invoke(args, *, timeout, limit=65536, stderr=False):
    # A regular output file plus inherited RLIMIT_FSIZE bounds native output
    # before Python reads it; the entire container also has an outer deadline.
    with tempfile.TemporaryFile(dir="/tmp") as output:
        completed = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.STDOUT if stderr else subprocess.DEVNULL, timeout=timeout, check=False)
        require(completed.returncode == 0); output.seek(0); raw = output.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def page_count(raw):
    text = raw.decode("utf-8", errors="strict")
    pages = re.findall(r"^Pages:\s+(\d+)\s*$", text, re.MULTILINE)
    encrypted = re.findall(r"^Encrypted:\s+(.+)$", text, re.MULTILINE)
    require(len(pages) == 1 and 1 <= int(pages[0]) <= MAX_PAGES
            and len(encrypted) == 1 and encrypted[0].strip() == "no")
    return int(pages[0])


def main():
    global STAGE
    require(len(sys.argv) == 1)
    os.umask(0o077)
    probes = isolation()  # Fail before consuming evidence or invoking a parser.
    STAGE = "tool_versions"
    versions = {}
    for name, args in (("pdftoppm", ["pdftoppm", "-v"]), ("tesseract", ["tesseract", "--version"])):
        version = invoke(args, timeout=5, limit=4096, stderr=True).decode("utf-8").splitlines()[0]
        require(0 < len(version) <= 256); versions[name] = version
    STAGE = "toolchain"
    toolchain = {"versions": versions, "worker_sha256": sha(bounded_read(__file__, 65536)),
        "package_inventory_sha256": sha(bounded_read("/opt/ai-dfir/packages.txt", 256 * 1024)),
        "english_model_sha256": sha(bounded_read("/usr/share/tesseract-ocr/5/tessdata/eng.traineddata", 32 * 1024**2)),
        "font_sha256": sha(bounded_read("/opt/ai-dfir/render-font.ttf", 2 * 1024**2))}
    STAGE = "input"
    raw = sys.stdin.buffer.read(SOURCE_BYTES + 1)
    require(0 < len(raw) <= SOURCE_BYTES and raw.startswith(b"%PDF-"))
    with tempfile.TemporaryDirectory(prefix="render-", dir="/tmp") as folder:
        source = Path(folder) / "source.pdf"
        with open(os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as stream: stream.write(raw)
        STAGE = "pdf_inventory"
        count = page_count(invoke(["pdfinfo", str(source)], timeout=5))
        rows, texts = [], []
        for number in range(1, count + 1):
            prefix = Path(folder) / f"page-{number:03}"
            STAGE = "raster"
            invoke(["pdftoppm", "-f", str(number), "-l", str(number), "-singlefile", "-gray", "-png",
                    "-r", "144", "-scale-to", str(MAX_SIDE), str(source), str(prefix)], timeout=10, limit=0)
            png = bounded_read(str(prefix) + ".png", PNG_BYTES)
            require(png.startswith(b"\x89PNG\r\n\x1a\n") and len(png) >= 33)
            width, height = struct.unpack(">II", png[16:24])
            require(1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE)
            STAGE = "ocr"
            text_raw = invoke(["tesseract", str(prefix) + ".png", "stdout", "-l", "eng", "--oem", "1", "--psm", "6"],
                              timeout=10, limit=TEXT_BYTES)
            text = text_raw.decode("utf-8", errors="strict"); texts.append(text)
            require(len("\n\f\n".join(texts).encode()) <= TEXT_BYTES)
            rows.append({"page": number, "width": width, "height": height, "png_sha256": sha(png), "png_size_bytes": len(png),
                         "png_base64": base64.b64encode(png).decode(), "ocr_text": text, "ocr_sha256": sha(text_raw)})
        visible = "\n\f\n".join(texts)
    report = {"schema": SCHEMA, "profile": PROFILE, "available": True, "source_sha256": sha(raw), "source_size_bytes": len(raw),
        "page_count": count, "pages": rows, "visible_text": visible, "visible_text_sha256": sha(visible.encode()),
        "toolchain": toolchain, "isolation": probes, "method": "raster-then-ocr", "rendering_performed": True,
        "source_authenticity_verified": False, "complete_visible_rendering_verified": False,
        "ocr_accuracy_verified": False, "collection_complete": None, "network_required": False}
    STAGE = "response"
    output = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    require(len(output) <= WIRE_BYTES); sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"schema": "ai-dfir/pdf-render-failure/v1.7", "stage": STAGE}))
        raise SystemExit(1)
