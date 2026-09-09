"""Protocol forgery, isolation refusal, bounded output, cleanup, and custody tests.

These tests use synthetic replies; native rendering is qualified by the separate
Docker workflow, never inferred from a protocol test passing.
"""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
from types import SimpleNamespace
import zlib

import pytest
import yaml

import v17_pdf_render as render
from v17_pdf_render_selftest import check, pdf_fixture, png_chunk, png_fixture, reply_fixture

ROOT = Path(render.__file__).resolve().parent
IMAGE = "sha256:" + "a" * 64
IDENTIFIER = "b" * 64
SOURCE = pdf_fixture()
spec = importlib.util.spec_from_file_location("pdf_render_worker", render.WORKER_SOURCE)
worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)


def info_fixture():
    return {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2", "ServerVersion": "synthetic-only",
            "MemoryLimit": True, "SwapLimit": True, "CpuCfsQuota": True, "PidsLimit": True,
            "SecurityOptions": ["name=seccomp,profile=builtin"]}


def image_fixture():
    return {"Id": IMAGE, "Os": "linux", "Architecture": "amd64", "Size": 100000,
            "Config": {"User": "65532:65532", "Entrypoint": ["python", "/opt/ai-dfir/render_worker.py"],
                       "Labels": {"org.ai-dfir.render-profile": render.PROFILE}}}


def container_fixture():
    return {"Id": IDENTIFIER, "Image": IMAGE, "Mounts": [],
            "Config": {"User": "65532:65532", "Entrypoint": ["python"], "Cmd": ["/opt/ai-dfir/render_worker.py"]},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "NetworkMode": "none", "IpcMode": "none",
                "PidMode": "", "CgroupnsMode": "private", "Memory": render.MEMORY_BYTES, "MemorySwap": render.MEMORY_BYTES,
                "NanoCpus": 1000000000, "PidsLimit": 64, "AutoRemove": False, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"], "Tmpfs": {"/tmp": render.TMPFS}, "LogConfig": {"Type": "none"},
                "Ulimits": [{"Name": name, "Soft": value, "Hard": value} for name, value in render.ULIMITS.items()]},
            "State": {"Status": "exited", "Running": False, "OOMKilled": False, "ExitCode": 0, "Error": ""}}


def unknown(result):
    assert result["available"] is False and result["artifact_set_complete"] is False
    assert result["findings"] == [{"type": "pdf_rendering_incomplete", "severity": "high"}]
    assert result["collection_complete"] is None
    assert all(result[key] is False for key in render.FALSE_FLAGS)


@pytest.fixture
def driver(monkeypatch):
    state = SimpleNamespace(calls=[], failure=None, cleanup_failure=False, interrupt=False, reply=reply_fixture(),
                            info=info_fixture(), image=image_fixture(), container=container_fixture())
    def command(binary, config, args, **kwargs):
        state.calls.append((args, kwargs))
        assert binary == "/usr/bin/docker" and Path(config).is_dir()
        phase = args[0]
        if phase == "rm":
            assert args[1] == "--force" and args[2].startswith("aidfir-render-")
            if state.cleanup_failure: raise OSError("cleanup unavailable")
            return b"removed\n"
        if phase == state.failure:
            if state.interrupt: raise KeyboardInterrupt
            raise subprocess.TimeoutExpired("redacted", 10)
        if phase == "info": return json.dumps(state.info).encode()
        if phase == "image": return json.dumps(state.image).encode()
        if phase == "create": return (IDENTIFIER + "\n").encode()
        if phase == "inspect": return json.dumps(state.container).encode()
        assert phase == "start" and kwargs == {"data": SOURCE, "limit": render.WIRE_BYTES, "timeout": 60}
        return state.reply if isinstance(state.reply, bytes) else json.dumps(state.reply).encode()
    monkeypatch.setattr(render, "command", command)
    monkeypatch.setattr(render.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(render.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(render.sys, "platform", "linux")
    return state


def test_protocol_selftest_never_claims_native_qualification():
    result = check()
    assert result == {"status": "PASS", "valid_protocol_replies": 1, "invalid_protocol_replies_rejected": 3,
                      "native_rendering_qualified": False, "network_required": False}


@pytest.mark.parametrize("key,value", [("schema", "other"), ("profile", "other"), ("available", 1),
    ("rendering_performed", None), ("source_sha256", "0" * 64), ("source_size_bytes", True),
    ("source_size_bytes", 1), ("page_count", 5), ("page_count", True), ("pages", []),
    ("visible_text", "forged"), ("visible_text_sha256", "0" * 64), ("method", "pdf-text-extraction"),
    ("collection_complete", True), ("extra", True)] + [(key, True) for key in sorted(render.FALSE_FLAGS)])
def test_forged_top_level_claim_is_unknown(driver, key, value):
    driver.reply[key] = value
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "response" and result["cleanup_complete"]
    assert result["rendering_performed"] is None


@pytest.mark.parametrize("key", sorted(render.PROBES))
def test_any_failed_isolation_observation_rejects_reply(driver, key):
    driver.reply["isolation"][key] = False
    unknown(render.render(SOURCE, selected_image=IMAGE))


@pytest.mark.parametrize("key,value", [("page", True), ("page", 2), ("width", True), ("height", 2),
    ("png_sha256", "0" * 64), ("png_size_bytes", True), ("png_base64", "!"),
    ("png_base64", base64.b64encode(png_fixture()).decode() + "\n"),
    ("ocr_text", "x" * 16385), ("ocr_text", "\ud800"), ("ocr_sha256", "0" * 64), ("extra", True)])
def test_forged_page_rejected(driver, key, value):
    driver.reply["pages"][0][key] = value
    unknown(render.render(SOURCE, selected_image=IMAGE))


@pytest.mark.parametrize("key", ["pages", "toolchain", "isolation", "source_sha256", "ocr_accuracy_verified"])
def test_missing_reply_fields_rejected(driver, key):
    del driver.reply[key]
    unknown(render.render(SOURCE, selected_image=IMAGE))


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b"null", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff"])
def test_invalid_json_rejected(driver, raw):
    driver.reply = raw; unknown(render.render(SOURCE, selected_image=IMAGE))


@pytest.mark.parametrize("key,value", [("worker_sha256", "0" * 64), ("package_inventory_sha256", "x"),
    ("english_model_sha256", None), ("font_sha256", "A" * 64), ("versions", {"pdftoppm": "x"}),
    ("versions", {"pdftoppm": "x", "tesseract": "x" * 257})])
def test_missing_or_mismatched_toolchain_rejected(driver, key, value):
    driver.reply["toolchain"][key] = value
    unknown(render.render(SOURCE, selected_image=IMAGE))


def png(*, width=1, height=1, depth=8, color=0, interlace=0, compressed=None, extra=b"", tail=b""):
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, interlace))
            + extra + png_chunk(b"IDAT", zlib.compress(b"\x00\xff") if compressed is None else compressed)
            + png_chunk(b"IEND", b"") + tail)


@pytest.mark.parametrize("raw", [png(width=0), png(width=2049), png(height=2049), png(depth=16), png(color=2),
    png(interlace=1), png(compressed=b"bad"), png(compressed=zlib.compress(b"\x05\xff")),
    png(compressed=zlib.compress(b"\x00")), png(compressed=zlib.compress(b"\x00" * 1000000)),
    png(compressed=zlib.compress(b"\x00\xff") + zlib.compress(b"extra")),
    png(extra=png_chunk(b"tEXt", b"hidden content")), png(extra=png_chunk(b"IHDR", b"")),
    png(tail=b"trailer"), png_fixture()[:-1], png_fixture()[:20] + b"\xff" + png_fixture()[21:]])
def test_malformed_or_excessive_png_rejected(raw):
    with pytest.raises((ValueError, zlib.error)): render.png_dimensions(raw)


def test_png_optional_physical_resolution_and_split_data_are_accepted():
    assert render.png_dimensions(png(extra=png_chunk(b"pHYs", struct.pack(">IIB", 5670, 5670, 1)))) == (1, 1)
    raw = png_fixture(); compressed = zlib.compress(b"\x00\xff")
    split = raw[:33] + png_chunk(b"IDAT", compressed[:3]) + png_chunk(b"IDAT", compressed[3:]) + png_chunk(b"IEND", b"")
    assert render.png_dimensions(split) == (1, 1)


@pytest.mark.parametrize("key,value", [("OSType", "windows"), ("Architecture", "arm64"), ("CgroupVersion", "1"),
    ("SecurityOptions", ["name=seccomp,profile=unconfined"]), ("ServerVersion", ""),
    ("MemoryLimit", False), ("SwapLimit", False), ("CpuCfsQuota", False), ("PidsLimit", False)])
def test_unsupported_daemon_never_creates_container(driver, key, value):
    driver.info[key] = value
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "daemon" and [call[0][0] for call in driver.calls] == ["info"]


@pytest.mark.parametrize("key,value", [("Id", "sha256:" + "c" * 64), ("Os", "windows"), ("Architecture", "arm64"),
    ("Size", True), ("Size", 3 * 1024**3), ("Config", {"User": "0"})])
def test_unsupported_image_never_creates_container(driver, key, value):
    driver.image[key] = value
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "image" and not any(call[0][0] == "create" for call in driver.calls)


@pytest.mark.parametrize("key,value", [("Privileged", True), ("ReadonlyRootfs", False), ("NetworkMode", "host"),
    ("IpcMode", "host"), ("PidMode", "host"), ("CgroupnsMode", "host"), ("Memory", 0), ("MemorySwap", -1),
    ("NanoCpus", 0), ("PidsLimit", -1), ("AutoRemove", True), ("CapDrop", []), ("CapAdd", ["SYS_ADMIN"]),
    ("SecurityOpt", []), ("Tmpfs", {}), ("LogConfig", {"Type": "json-file"}), ("Binds", ["/:/host"]),
    ("Mounts", [{"Target": "/host"}]), ("Devices", [{"PathOnHost": "/dev/sda"}]),
    ("DeviceRequests", [{}]), ("VolumesFrom", ["other"]), ("Ulimits", [])])
def test_changed_container_controls_prevent_start_and_clean_up(driver, key, value):
    driver.container["HostConfig"][key] = value
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "container" and result["cleanup_complete"]
    assert result["rendering_performed"] is False and not any(call[0][0] == "start" for call in driver.calls)
    assert driver.calls[-1][0][0] == "rm"


@pytest.mark.parametrize("key,value", [("Status", "running"), ("Running", True), ("OOMKilled", True),
    ("ExitCode", 1), ("ExitCode", False), ("Error", "failed")])
def test_failed_final_state_is_unknown(driver, key, value):
    driver.container["State"][key] = value
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "render" and result["rendering_performed"] is None and result["cleanup_complete"]


def test_boolean_limit_is_not_an_integer_control(driver):
    driver.container["HostConfig"]["Ulimits"][0]["Soft"] = False
    unknown(render.render(SOURCE, selected_image=IMAGE))


@pytest.mark.parametrize("phase", ["info", "image", "create", "inspect", "start"])
def test_command_failure_cleans_up_only_our_attempted_container(driver, phase):
    driver.failure = phase
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["cleanup_complete"]
    assert (driver.calls[-1][0][0] == "rm") is (phase not in {"info", "image"})


def test_cleanup_failure_prevents_success_and_retains_only_container_diagnostic(driver):
    driver.cleanup_failure = True
    result = render.render(SOURCE, selected_image=IMAGE); unknown(result)
    assert result["stage"] == "cleanup" and result["cleanup_complete"] is False
    assert result["container_name"] == driver.calls[-1][0][2] and "visible_text" not in result


def test_interrupt_still_cleans_up(driver):
    driver.failure, driver.interrupt = "start", True
    with pytest.raises(KeyboardInterrupt): render.render(SOURCE, selected_image=IMAGE)
    assert driver.calls[-1][0][0] == "rm"


def test_fixed_driver_order_and_bound_image(driver):
    result = render.render(SOURCE, selected_image=IMAGE)
    assert result["available"] and result["cleanup_complete"] and result["container_image_id"] == IMAGE
    assert [call[0][0] for call in driver.calls] == ["info", "image", "create", "inspect", "start", "inspect", "rm"]
    args = driver.calls[2][0]
    assert args[-2:] == [IMAGE, "/opt/ai-dfir/render_worker.py"]
    assert "--pull=never" in args and "--network=none" in args and "--read-only" in args
    assert "--volume" not in args and "--mount" not in args and "--privileged" not in args


@pytest.mark.parametrize("selected", ["latest", "image:tag", "sha256:" + "A" * 64, "sha256:" + "a" * 63, None])
def test_mutable_or_invalid_image_cannot_invoke_engine(driver, selected):
    unknown(render.render(SOURCE, selected_image=selected)); assert driver.calls == []


@pytest.mark.parametrize("source", [b"", b"not a PDF", b"%PDF-" + b"x" * render.SOURCE_BYTES, None, "pdf", bytearray(b"%PDF-")])
def test_invalid_source_never_invokes_engine(driver, source):
    unknown(render.render(source, selected_image=IMAGE)); assert driver.calls == []


def test_docker_environment_and_output_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted:2375")
    monkeypatch.setenv("PRIVATE_VALUE", "never-forward")
    def run(args, **kw):
        assert args[:4] == ["/usr/bin/docker", "--config", str(tmp_path), "--host=unix:///var/run/docker.sock"]
        assert kw["env"] == {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
        assert kw["timeout"] == 10 and kw["stderr"] == subprocess.DEVNULL and "shell" not in kw
        assert callable(kw["preexec_fn"])
        kw["stdout"].write(b"x" * 17)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(render.subprocess, "run", run)
    with pytest.raises(ValueError): render.command("/usr/bin/docker", tmp_path, ["info"], limit=16)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux resource limits")
def test_actual_parent_cli_output_file_limit(tmp_path):
    # A trusted test executable verifies the child's limits and overruns stdout.
    binary = tmp_path / "fake-docker"
    binary.write_text(f"#!{sys.executable}\nimport os,resource\nassert resource.getrlimit(resource.RLIMIT_FSIZE)==(1024,1024)\nassert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\nos.write(1,b'x'*2048)\nos.write(1,b'x')\n")
    binary.chmod(0o700)
    with pytest.raises(ValueError): render.command(str(binary), tmp_path, ["info"], limit=1024)


@pytest.fixture
def isolated_worker(monkeypatch):
    state = SimpleNamespace(uid=65532, gid=65532, net=["lo"], connected=101, tmp_bytes=render.TMPFS_BYTES,
        files={"/proc/self/status": b"NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t00000000\nCapBnd:\t00000000\n",
               "/sys/fs/cgroup/memory.max": str(render.MEMORY_BYTES).encode(), "/sys/fs/cgroup/memory.swap.max": b"0",
               "/sys/fs/cgroup/pids.max": b"64", "/sys/fs/cgroup/cpu.max": b"100000 100000",
               "/proc/self/mountinfo": b"1 2 0:1 / / ro - overlay overlay ro\n2 1 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"},
        limits={resource.RLIMIT_CORE: (0, 0), resource.RLIMIT_FSIZE: (render.SOURCE_BYTES,) * 2,
                resource.RLIMIT_CPU: (30, 30), resource.RLIMIT_NOFILE: (64, 64)})
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): assert value == 0.2
        def connect_ex(self, address): assert address == ("192.0.2.1", 443); return state.connected
    monkeypatch.setattr(worker.os, "getuid", lambda: state.uid)
    monkeypatch.setattr(worker.os, "getgid", lambda: state.gid)
    monkeypatch.setattr(worker.os, "listdir", lambda path: state.net)
    monkeypatch.setattr(worker.os, "statvfs", lambda path: SimpleNamespace(f_frsize=1, f_blocks=state.tmp_bytes))
    monkeypatch.setattr(worker.socket, "socket", Socket)
    monkeypatch.setattr(worker, "bounded_read", lambda path, limit: state.files[str(path)])
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: state.limits[kind])
    return state


def test_worker_accepts_only_observed_profile(isolated_worker):
    assert worker.isolation() == {key: True for key in render.PROBES}


@pytest.mark.parametrize("key,value", [("uid", 0), ("gid", 0), ("net", ["lo", "eth0"]),
    ("connected", 0), ("tmp_bytes", render.TMPFS_BYTES + 1)])
def test_worker_identity_network_tmpfs_fail_closed(isolated_worker, key, value):
    setattr(isolated_worker, key, value)
    with pytest.raises(ValueError): worker.isolation()


@pytest.mark.parametrize("path,value", [("/proc/self/status", b"NoNewPrivs: 0\nSeccomp: 2\nCapEff: 0\nCapBnd: 0\n"),
    ("/proc/self/status", b"NoNewPrivs: 1\nSeccomp: 0\nCapEff: 0\nCapBnd: 0\n"),
    ("/proc/self/status", b"NoNewPrivs: 1\nSeccomp: 2\nCapEff: 1\nCapBnd: 0\n"),
    ("/proc/self/status", b"NoNewPrivs: 1\nSeccomp: 2\nCapEff: 0\nCapBnd: 1\n"),
    ("/sys/fs/cgroup/memory.max", b"max"), ("/sys/fs/cgroup/memory.swap.max", b"max"),
    ("/sys/fs/cgroup/pids.max", b"max"), ("/sys/fs/cgroup/cpu.max", b"max 100000"),
    ("/proc/self/mountinfo", b"1 2 0:1 / / rw - overlay overlay rw\n")])
def test_worker_kernel_observations_are_required(isolated_worker, path, value):
    isolated_worker.files[path] = value
    with pytest.raises(ValueError): worker.isolation()


@pytest.mark.parametrize("kind", [resource.RLIMIT_CORE, resource.RLIMIT_FSIZE, resource.RLIMIT_CPU, resource.RLIMIT_NOFILE])
def test_worker_process_limits_are_required(isolated_worker, kind):
    isolated_worker.limits[kind] = (resource.RLIM_INFINITY,) * 2
    with pytest.raises(ValueError): worker.isolation()


def test_worker_refuses_before_evidence_or_native_parser(monkeypatch):
    monkeypatch.setattr(worker.sys, "argv", ["worker"])
    monkeypatch.setattr(worker.os, "umask", lambda value: None)
    monkeypatch.setattr(worker, "isolation", lambda: (_ for _ in ()).throw(ValueError("unisolated")))
    monkeypatch.setattr(worker, "invoke", lambda *a, **k: pytest.fail("native parser called"))
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=SimpleNamespace(read=lambda *a: pytest.fail("evidence consumed"))))
    with pytest.raises(ValueError): worker.main()


@pytest.mark.parametrize("raw", [b"Pages: 0\nEncrypted: no\n", b"Pages: 5\nEncrypted: no\n",
    b"Pages: 1\nEncrypted: yes (print:yes)\n", b"Pages: 1\nPages: 2\nEncrypted: no\n",
    b"Pages: 1\n", b"Encrypted: no\n", b"\xff", b"Pages: 1\nEncrypted: no\nEncrypted: no\n"])
def test_encrypted_excessive_or_ambiguous_page_inventory_rejected(raw):
    with pytest.raises(ValueError): worker.page_count(raw)


@pytest.mark.parametrize("pages", [1, 2, 3, 4])
def test_bounded_page_inventory(pages):
    assert worker.page_count(f"Title: synthetic\nPages: {pages}\nEncrypted: no\n".encode()) == pages


def test_capture_retains_bound_private_artifacts_and_receipt_last(tmp_path, driver, monkeypatch):
    source = tmp_path / "input.pdf"; source.write_bytes(SOURCE)
    destination = tmp_path / "rendered"; order = []; original = render.private_write
    def write(path, raw): order.append(path.name); original(path, raw)
    monkeypatch.setattr(render, "private_write", write)
    report = render.capture(source, destination, selected_image=IMAGE)
    assert report["artifact_set_complete"] and report["rendering_performed"]
    assert json.loads((destination / "render.json").read_bytes()) == report
    assert (destination / "source.pdf").read_bytes() == SOURCE and source.read_bytes() == SOURCE
    assert (destination / "visible.txt").read_text() == report["visible_text"]
    assert (destination / "page-001.png").read_bytes() == png_fixture()
    assert "png_base64" not in report["pages"][0] and order == ["source.pdf", "visible.txt", "page-001.png"]
    assert destination.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir())


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "source"])
def test_capture_preserves_existing_output_and_source(tmp_path, driver, kind):
    source = tmp_path / "input.pdf"; source.write_bytes(SOURCE)
    destination = source if kind == "source" else tmp_path / "rendered"
    if kind == "file": destination.write_bytes(b"retained")
    elif kind == "directory": destination.mkdir()
    elif kind == "symlink": destination.symlink_to(source)
    with pytest.raises(OSError): render.capture(source, destination, selected_image=IMAGE)
    assert source.read_bytes() == SOURCE
    if kind == "file": assert destination.read_bytes() == b"retained"


def test_partial_write_never_creates_completion_receipt(tmp_path, driver, monkeypatch):
    source = tmp_path / "input.pdf"; source.write_bytes(SOURCE); directory = tmp_path / "rendered"
    original = render.private_write
    def write(path, raw):
        if path.name == "visible.txt": raise OSError("synthetic disk full")
        original(path, raw)
    monkeypatch.setattr(render, "private_write", write)
    with pytest.raises(OSError): render.capture(source, directory, selected_image=IMAGE)
    assert (directory / "source.pdf").read_bytes() == SOURCE and not (directory / "render.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversize", "missing", "directory"])
def test_snapshot_refuses_nonregular_or_excessive_sources(tmp_path, driver, kind):
    source = tmp_path / "input.pdf"; retained = tmp_path / "retained"; retained.write_bytes(SOURCE)
    if kind == "symlink": source.symlink_to(retained)
    elif kind == "fifo": os.mkfifo(source)
    elif kind == "oversize": source.write_bytes(b"x" * (render.SOURCE_BYTES + 1))
    elif kind == "directory": source.mkdir()
    with pytest.raises((ValueError, OSError)): render.capture(source, tmp_path / "out", selected_image=IMAGE)
    assert driver.calls == [] and retained.read_bytes() == SOURCE


def test_unavailable_capture_creates_no_directory(tmp_path, driver):
    source = tmp_path / "input.pdf"; source.write_bytes(SOURCE); driver.failure = "start"
    unknown(render.capture(source, tmp_path / "out", selected_image=IMAGE))
    assert not (tmp_path / "out").exists()


def test_qualification_workflow_requires_actual_rendering_and_retention():
    workflow = yaml.safe_load((ROOT / ".github/workflows/pdf-render-qualification.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["qualify"]; assert job["runs-on"] == "ubuntu-24.04"
    steps = job["steps"]
    actual = next(step for step in steps if step.get("name") == "Qualify actual isolated rendering and OCR")
    assert "scripts/qualify_pdf_render_v17.py" in actual["run"]
    assert all(not step.get("continue-on-error") for step in steps) and "if" not in actual
    upload = steps[-1]; assert upload["if"] == "always()" and upload["with"]["retention-days"] == 14
    assert "upload-artifact@" in upload["uses"]


def test_worker_and_parent_profile_limits_match():
    for name in ("SCHEMA", "PROFILE", "SOURCE_BYTES", "PNG_BYTES", "WIRE_BYTES", "TEXT_BYTES", "MAX_PAGES", "MAX_SIDE", "MEMORY_BYTES", "TMPFS_BYTES"):
        assert getattr(worker, name) == getattr(render, name)
