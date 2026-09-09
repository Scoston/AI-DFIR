"""Explicit isolated PDF raster/OCR capture through a locally pinned Docker image."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

from v17_content_intake import read_snapshot, output_report, _object, _constant, require
from v17_integrity import canonical_json_bytes, sha256_bytes

ROOT = Path(__file__).resolve().parent
WORKER_SOURCE = ROOT / "deploy/render/worker.py"
SCHEMA = "ai-dfir/isolated-pdf-render/v1.7"
PROFILE = "pdf-raster-ocr-v1.7"
SOURCE_BYTES = 8 * 1024**2
PNG_BYTES = 5 * 1024**2
WIRE_BYTES = 32 * 1024**2
REPORT_BYTES = 256 * 1024
TEXT_BYTES = 16 * 1024
MAX_PAGES = 4
MAX_SIDE = 2048
MEMORY_BYTES = 512 * 1024**2
TMPFS_BYTES = 64 * 1024**2
TMPFS = "rw,noexec,nosuid,nodev,size=67108864,mode=1777"
PROBES = {"nonroot", "capabilities_dropped", "no_new_privileges", "seccomp_filter", "network_none",
          "root_read_only", "tmpfs_bounded_noexec", "memory_swap_cpu_pids_limits", "process_limits"}
FALSE_FLAGS = {"source_authenticity_verified", "complete_visible_rendering_verified", "ocr_accuracy_verified", "network_required"}
ULIMITS = {"core": 0, "fsize": SOURCE_BYTES, "cpu": 30, "nofile": 64}


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def image_id(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= WIRE_BYTES)
    return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)


def png_dimensions(raw):
    """Validate the narrow grayscale PNG profile without a host image library."""
    require(type(raw) is bytes and 45 <= len(raw) <= PNG_BYTES and raw[:8] == b"\x89PNG\r\n\x1a\n")
    offset, count, ended, physical = 8, 0, False, False
    width = height = None
    compressed = []
    while offset < len(raw):
        require(not ended and count < 128 and offset + 12 <= len(raw)); count += 1
        length = struct.unpack(">I", raw[offset:offset + 4])[0]
        kind = raw[offset + 4:offset + 8]; end = offset + 12 + length
        require(end <= len(raw)); body = raw[offset + 8:end - 4]
        require(zlib.crc32(kind + body) == struct.unpack(">I", raw[end - 4:end])[0])
        if kind == b"IHDR":
            require(count == 1 and length == 13)
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
            require(1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE
                    and (depth, color, compression, filtering, interlace) == (8, 0, 0, 0, 0))
        elif kind == b"pHYs":
            require(width is not None and not physical and not compressed and length == 9)
            physical = True
        elif kind == b"IDAT":
            require(width is not None); compressed.append(body)
        elif kind == b"IEND":
            require(width is not None and compressed and length == 0); ended = True
        else:
            require(False)
        offset = end
    require(ended)
    expected = height * (width + 1)
    decoder = zlib.decompressobj(); pixels = decoder.decompress(b"".join(compressed), expected + 1)
    require(len(pixels) == expected and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and all(value <= 4 for value in pixels[::width + 1]))
    return width, height


def validate(report, source):
    require(type(source) is bytes and 0 < len(source) <= SOURCE_BYTES and source.startswith(b"%PDF-"))
    keys = {"schema", "profile", "available", "source_sha256", "source_size_bytes", "page_count", "pages", "visible_text",
            "visible_text_sha256", "toolchain", "isolation", "method", "rendering_performed", "collection_complete"} | FALSE_FLAGS
    require(isinstance(report, dict) and set(report) == keys and report["schema"] == SCHEMA
            and report["profile"] == PROFILE and report["available"] is True and report["rendering_performed"] is True
            and report["source_sha256"] == sha256_bytes(source) and type(report["source_size_bytes"]) is int
            and report["source_size_bytes"] == len(source) and report["collection_complete"] is None
            and report["method"] == "raster-then-ocr" and all(report[key] is False for key in FALSE_FLAGS))
    probes = report["isolation"]
    require(isinstance(probes, dict) and set(probes) == PROBES and all(value is True for value in probes.values()))
    chain = report["toolchain"]
    require(isinstance(chain, dict) and set(chain) == {"versions", "worker_sha256", "package_inventory_sha256", "english_model_sha256", "font_sha256"}
            and all(digest(chain[key]) for key in chain if key != "versions")
            and chain["worker_sha256"] == sha256_bytes(WORKER_SOURCE.read_bytes()))
    versions = chain["versions"]
    require(isinstance(versions, dict) and set(versions) == {"pdftoppm", "tesseract"}
            and all(isinstance(value, str) and 0 < len(value) <= 256 for value in versions.values()))
    require(type(report["page_count"]) is int and 1 <= report["page_count"] <= MAX_PAGES
            and isinstance(report["pages"], list) and len(report["pages"]) == report["page_count"])
    images, texts = [], []
    for number, row in enumerate(report["pages"], 1):
        require(isinstance(row, dict) and set(row) == {"page", "width", "height", "png_sha256", "png_size_bytes", "png_base64", "ocr_text", "ocr_sha256"}
                and type(row["page"]) is int and row["page"] == number
                and isinstance(row["png_base64"], str) and len(row["png_base64"]) <= 4 * ((PNG_BYTES + 2) // 3))
        png = base64.b64decode(row["png_base64"], validate=True)
        require(base64.b64encode(png).decode() == row["png_base64"] and row["png_sha256"] == sha256_bytes(png)
                and type(row["png_size_bytes"]) is int and row["png_size_bytes"] == len(png))
        width, height = png_dimensions(png)
        require(type(row["width"]) is int and type(row["height"]) is int and (width, height) == (row["width"], row["height"]))
        text = row["ocr_text"]
        require(isinstance(text, str) and len(text) <= TEXT_BYTES and len(text.encode()) <= TEXT_BYTES
                and row["ocr_sha256"] == sha256_bytes(text.encode()))
        images.append(png); texts.append(text)
    visible = "\n\f\n".join(texts)
    require(len(visible.encode()) <= TEXT_BYTES and report["visible_text"] == visible
            and report["visible_text_sha256"] == sha256_bytes(visible.encode()))
    return images


def info_check(info):
    require(isinstance(info, dict) and info.get("OSType") == "linux" and info.get("Architecture") in {"x86_64", "amd64"}
            and info.get("CgroupVersion") == "2" and isinstance(info.get("ServerVersion"), str)
            and 0 < len(info["ServerVersion"]) <= 128
            and all(info.get(key) is True for key in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"))
            and "name=seccomp,profile=builtin" in info.get("SecurityOptions", []))


def image_check(info, selected):
    require(isinstance(info, dict) and info.get("Id") == selected and info.get("Os") == "linux"
            and info.get("Architecture") == "amd64" and type(info.get("Size")) is int and 0 < info["Size"] <= 2 * 1024**3)
    config = info.get("Config")
    require(isinstance(config, dict) and not config.get("Volumes") and config.get("User") == "65532:65532"
            and config.get("Entrypoint") == ["python", "/opt/ai-dfir/render_worker.py"]
            and config.get("Labels", {}).get("org.ai-dfir.render-profile") == PROFILE)


def create_args(name, selected):
    image_id(selected); require(re.fullmatch(r"aidfir-render-[0-9a-f]{32}", name))
    args = ["create", "--interactive", "--name", name, "--pull=never", "--read-only", "--network=none", "--ipc=none",
            "--cgroupns=private", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=65532:65532",
            "--memory=536870912", "--memory-swap=536870912", "--cpus=1", "--pids-limit=64", "--log-driver=none",
            "--tmpfs", "/tmp:" + TMPFS, "--workdir=/tmp", "--no-healthcheck", "--entrypoint=python"]
    for key, value in ULIMITS.items(): args.append(f"--ulimit={key}={value}:{value}")
    return args + [selected, "/opt/ai-dfir/render_worker.py"]


def container_check(info, selected, *, stopped=False):
    require(isinstance(info, dict) and digest(info.get("Id")) and info.get("Image") == selected)
    config, host = info.get("Config"), info.get("HostConfig")
    require(isinstance(config, dict) and isinstance(host, dict) and config.get("User") == "65532:65532"
            and config.get("Entrypoint") == ["python"] and config.get("Cmd") == ["/opt/ai-dfir/render_worker.py"]
            and not config.get("Volumes") and not info.get("Mounts"))
    expected = {"Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "none", "IpcMode": "none", "PidMode": "",
                "CgroupnsMode": "private", "Memory": MEMORY_BYTES, "MemorySwap": MEMORY_BYTES, "NanoCpus": 1000000000,
                "PidsLimit": 64, "AutoRemove": False}
    require(all(host.get(key) == value and type(host.get(key)) is type(value) for key, value in expected.items())
            and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd")
            and host.get("SecurityOpt") == ["no-new-privileges:true"] and host.get("Tmpfs") == {"/tmp": TMPFS}
            and host.get("LogConfig", {}).get("Type") == "none"
            and all(not host.get(key) for key in ("Binds", "Mounts", "Devices", "DeviceRequests", "VolumesFrom")))
    limits = host.get("Ulimits")
    require(isinstance(limits, list) and len(limits) == len(ULIMITS)
            and all(isinstance(row, dict) and type(row.get("Soft")) is int and type(row.get("Hard")) is int for row in limits)
            and {row.get("Name"): (row.get("Soft"), row.get("Hard")) for row in limits if isinstance(row, dict)}
            == {key: (value, value) for key, value in ULIMITS.items()})
    if stopped:
        state = info.get("State")
        require(isinstance(state, dict) and state.get("Status") == "exited" and state.get("Running") is False
                and state.get("OOMKilled") is False and type(state.get("ExitCode")) is int and state["ExitCode"] == 0
                and not state.get("Error"))


def command(binary, config, args, *, data=None, limit=65536, timeout=10):
    import resource
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryFile() as output:
        result = subprocess.run([binary, "--config", str(config), "--host=unix:///var/run/docker.sock", *args], input=data,
                    stdout=output, stderr=subprocess.DEVNULL, timeout=timeout, preexec_fn=limits,
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}, check=False)
        output.seek(0); raw = output.read(limit + 1)
    require(result.returncode == 0 and len(raw) <= limit)
    return raw


def render(source, *, selected_image):
    unknown = {"schema": SCHEMA, "profile": PROFILE, "available": False, "rendering_performed": False,
        "error": "rendering unavailable, unsupported, invalid, or resource-limited", "stage": "input", "cleanup_complete": True,
        "artifact_set_complete": False,
        "findings": [{"type": "pdf_rendering_incomplete", "severity": "high"}], "collection_complete": None,
        **{key: False for key in FALSE_FLAGS}}
    name, attempted, cleaned, report = "aidfir-render-" + uuid.uuid4().hex, False, True, None
    try:
        require(type(source) is bytes and 0 < len(source) <= SOURCE_BYTES)
        unknown.update(source_sha256=sha256_bytes(source), source_size_bytes=len(source))
        require(source.startswith(b"%PDF-")); image_id(selected_image)
        require(sys.platform == "linux" and platform.machine() == "x86_64")
        binary = shutil.which("docker"); require(binary is not None)
        with tempfile.TemporaryDirectory(prefix="aidfir-docker-config-") as config:
            try:
                unknown["stage"] = "daemon"
                info = parse(command(binary, config, ["info", "--format", "{{json .}}"])); info_check(info)
                unknown["stage"] = "image"
                image_check(parse(command(binary, config, ["image", "inspect", selected_image, "--format", "{{json .}}"])), selected_image)
                unknown["stage"] = "container"
                attempted, cleaned = True, False
                identifier = command(binary, config, create_args(name, selected_image)).decode().strip()
                require(digest(identifier))
                inspect = lambda: parse(command(binary, config, ["inspect", identifier, "--format", "{{json .}}"] ))
                container_check(inspect(), selected_image)
                unknown["stage"] = "render"
                unknown["rendering_performed"] = None  # A failed attempt may have produced partial pages.
                raw = command(binary, config, ["start", "--attach", "--interactive", identifier], data=source, limit=WIRE_BYTES, timeout=60)
                container_check(inspect(), selected_image, stopped=True)
                unknown["stage"] = "response"
                report = parse(raw); validate(report, source)
                report.update(container_image_id=selected_image, docker_server_version=info["ServerVersion"], container_configuration_checked=True)
            finally:
                if attempted:
                    try: command(binary, config, ["rm", "--force", name], limit=4096); cleaned = True
                    except Exception: cleaned = False
        if cleaned and report is not None:
            report["cleanup_complete"] = True
            return report
    except Exception:
        pass
    unknown["cleanup_complete"] = cleaned
    if not cleaned: unknown.update(stage="cleanup", container_name=name)
    return unknown


def private_write(path, raw):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def capture(path, destination, *, selected_image):
    source = read_snapshot(path, SOURCE_BYTES)
    report = render(source, selected_image=selected_image)
    if report["available"] is not True: return report
    require(report.get("container_image_id") == image_id(selected_image)
            and report.get("container_configuration_checked") is True and report.get("cleanup_complete") is True)
    # Validate again after transport metadata is removed, before any artifact writes.
    wire = {key: value for key, value in report.items() if key not in
            {"container_image_id", "docker_server_version", "container_configuration_checked", "cleanup_complete"}}
    images = validate(wire, source)
    directory = Path(destination).absolute(); directory.mkdir(mode=0o700)
    private_write(directory / "source.pdf", source)
    private_write(directory / "visible.txt", report["visible_text"].encode())
    for row, png in zip(report["pages"], images, strict=True):
        row.pop("png_base64"); row["png_file"] = f"page-{row['page']:03}.png"
        private_write(directory / row["png_file"], png)
    report.update(artifact_set_complete=True, source_file="source.pdf", visible_text_file="visible.txt")
    # The completion receipt is written last; a partial directory is never complete.
    output_report(report, directory / "render.json", limit=REPORT_BYTES)
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("pdf"); parser.add_argument("--image-id", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    try:
        report = capture(args.pdf, args.out_dir, selected_image=args.image_id)
        output = {key: report[key] for key in ("schema", "available", "rendering_performed", "artifact_set_complete")} if report["available"] else report
        print(json.dumps(output, sort_keys=True))
        return 0 if report["available"] else 1
    except KeyboardInterrupt: return 130
    except Exception:
        print(json.dumps({"available": False, "artifact_set_complete": False, "error": "invalid input or unavailable output"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
