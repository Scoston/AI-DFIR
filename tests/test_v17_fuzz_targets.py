"""Fuzz-oracle fault injection and fail-closed runner acceptance, without Atheris."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import zipfile

import pytest
import yaml

import v17_fuzz_targets as targets
from v17_fuzz_targets_selftest import check
from scripts import run_coverage_fuzz_v17 as runner

SEEDS = targets.seed_inputs()
DONE = b"#100 DONE cov: 12 ft: 15 corp: 3/40b\nstat::number_of_executed_units: 100\n"


@pytest.mark.parametrize("index", range(20))
def test_all_seed_profiles_and_source_bindings(index):
    with targets.blocked_actions():
        status, digest = targets.exercise(SEEDS[index])
    assert status == "ACCEPT" and len(digest) == 64


@pytest.mark.parametrize("index", range(20))
def test_all_empty_payloads_reject(index):
    with targets.blocked_actions():
        assert targets.exercise(bytes([index])) == ("REJECT", None)


@pytest.mark.parametrize("raw", [b"", b"\x14", b"\xff", b"\x80import os"])
def test_unknown_selectors_do_not_call_parser(raw, monkeypatch):
    monkeypatch.setattr(targets.providers, "_outcome", lambda *a: pytest.fail("unexpected dispatch"))
    monkeypatch.setattr(targets.archives, "_outcome", lambda *a: pytest.fail("unexpected dispatch"))
    assert targets.exercise(raw) == ("IGNORED", None)


@pytest.mark.parametrize("raw", [None, "", [], bytearray(b"a"), memoryview(b"a"), b"x" * (targets.MAX_INPUT_BYTES + 1)])
def test_bad_input_type_or_size(raw):
    with pytest.raises(ValueError): targets.exercise(raw)


def test_exact_maximum_input_is_bounded_and_rejected():
    assert targets.exercise(b"\x00" * targets.MAX_INPUT_BYTES) == ("REJECT", None)


@pytest.mark.parametrize("status,error", [("CRASH", "RuntimeError"), ("INVARIANT_FAILURE", "AssertionError"),
                                           ("UNKNOWN", None), ("ACCEPT", "ignored failure")])
def test_provider_failure_is_fuzzer_failure(monkeypatch, status, error):
    monkeypatch.setattr(targets.providers, "_outcome", lambda *a: (status, None, error))
    with pytest.raises(AssertionError): targets.exercise(SEEDS[0])


@pytest.mark.parametrize("flag,value", [("source_authenticity_verified", True), ("network_required", True),
                                        ("collection_complete", True), ("source_sha256", "0" * 64)])
def test_real_provider_oracle_detects_forged_claims(monkeypatch, flag, value):
    profile = targets.PROVIDERS[0]
    projected = profile.normalize(profile.seed)
    projected[flag] = value
    monkeypatch.setattr(profile.module, "normalize", lambda *a, **kw: copy.deepcopy(projected))
    with pytest.raises(AssertionError): targets.exercise(SEEDS[0])


@pytest.mark.parametrize("flag", ["members_extracted", "member_payload_integrity_verified", "archive_safety_verified",
                                  "source_authenticity_verified", "extraction_authorized", "network_required"])
def test_real_archive_oracle_detects_forged_claims(monkeypatch, flag):
    report = targets.archives.inspect_archive(SEEDS[12][1:], input_format="zip")
    report[flag] = True
    monkeypatch.setattr(targets.archives, "inspect_archive", lambda *a, **kw: copy.deepcopy(report))
    with pytest.raises(AssertionError): targets.exercise(SEEDS[12])


@pytest.mark.parametrize("flag,value", [("source_sha256", "0" * 64), ("selected_part_size_crc_checked", False),
    ("all_member_payloads_verified", True), ("external_resources_loaded", True), ("filesystem_extraction", True),
    ("source_authenticity_verified", True), ("complete_visible_rendering_verified", True), ("network_required", True)])
def test_docx_oracle_detects_forged_claims(monkeypatch, flag, value):
    parts = targets.docx.load_docx(SEEDS[17][1:])
    parts.intake[flag] = value
    monkeypatch.setattr(targets.docx, "load_docx", lambda raw: copy.deepcopy(parts))
    with pytest.raises(AssertionError): targets.exercise(SEEDS[17])


@pytest.mark.parametrize("selector", [18, 19])
@pytest.mark.parametrize("flag,value", [("source_sha256", "0" * 64), ("filesystem_resources_loaded", True),
    ("font_geometry_verified", True), ("source_authenticity_verified", True),
    ("complete_visible_rendering_verified", True), ("network_required", True)])
def test_html_css_oracle_detects_forged_claims(selector, flag, value, monkeypatch):
    report = targets.html.inspect_static(SEEDS[selector][1:], input_format="html" if selector == 18 else "css")
    report[flag] = value
    monkeypatch.setattr(targets.html, "inspect_static", lambda *a, **kw: copy.deepcopy(report))
    with pytest.raises(AssertionError): targets.exercise(SEEDS[selector])


@pytest.mark.parametrize("selector", [0, 12])
def test_nondeterminism_is_failure(monkeypatch, selector):
    rows = iter([("ACCEPT", "a"), ("ACCEPT", "b")])
    if selector == 0:
        monkeypatch.setattr(targets.providers, "_outcome", lambda *a: (*next(rows), None))
    else:
        monkeypatch.setattr(targets.archives, "_outcome", lambda *a: next(rows))
    with pytest.raises(AssertionError, match="nondeterministic"): targets.exercise(SEEDS[selector])


@pytest.mark.parametrize("owner,name", [(socket.socket, "connect"), (socket.socket, "connect_ex"),
    (socket.socket, "sendto"), (socket, "create_connection"), (socket, "getaddrinfo"),
    (subprocess, "Popen"), (os, "system"), (zipfile.ZipFile, "open"), (zipfile.ZipFile, "extract"),
    (zipfile.ZipFile, "extractall"), (tarfile.TarFile, "extractfile"), (tarfile.TarFile, "extract"),
    (tarfile.TarFile, "extractall")])
def test_action_tripwires_restore_after_failure(owner, name):
    original = getattr(owner, name)
    with pytest.raises(AssertionError, match="blocked"):
        with targets.blocked_actions(): getattr(owner, name)()
    assert getattr(owner, name) is original


def test_seed_preflight_pins_and_no_engine_claim():
    report = check()
    assert report["status"] == "PASS" and report["coverage_guided"] is False
    assert len({row["selector"] for row in report["rows"]}) == 20


def test_instrumentation_modules_match_without_importing_engine():
    tree = ast.parse((runner.ROOT / "scripts/fuzz_parsers_v17.py").read_text())
    assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "modules" for t in n.targets))
    assert ast.literal_eval(assignment.value) == targets.INSTRUMENTED_MODULES


def test_optimized_python_fails_closed():
    result = subprocess.run([sys.executable, "-O", "-c", "import v17_fuzz_targets as t; t.exercise(b'')"],
                            cwd=runner.ROOT, capture_output=True)
    assert result.returncode != 0 and b"assertions must be enabled" in result.stderr


@pytest.mark.parametrize("runs", [True, None, 99, 20001, "500", 100.0])
def test_runs_bounds(runs):
    with pytest.raises(ValueError): runner.options(runs, 1)


@pytest.mark.parametrize("seed", [True, None, 0, -1, 4294967296, "1", 1.0])
def test_seed_bounds(seed):
    with pytest.raises(ValueError): runner.options(100, seed)


@pytest.mark.parametrize("runs,seed", [(100, 1), (20000, 4294967295)])
def test_limit_endpoints(runs, seed):
    runner.options(runs, seed)


@pytest.mark.parametrize("raw", [b"", DONE + DONE, DONE.replace(b"#100", b"#99"),
    DONE.replace(b"cov: 12", b"cov: 0"), DONE.replace(b"ft: 15", b"ft: 0"),
    DONE.replace(b"units: 100", b"units: 99"), DONE.splitlines()[0] + b"\n",
    b"PASS: 100 runs"])
def test_missing_partial_or_ambiguous_completion_fails(raw):
    with pytest.raises(RuntimeError): runner.completion(raw, 100)


def test_native_completion_is_counters_not_percent():
    assert runner.completion(DONE, 100) == {"executed_units": 100, "coverage_counters": 12, "features": 15}


def test_command_uses_fixed_limits_and_no_shell():
    cmd = runner.command(Path("space corpus"), Path("x;echo unsafe"), 100, 17019)
    assert cmd[:3] == [sys.executable, str(runner.ROOT / "scripts/fuzz_parsers_v17.py"), "space corpus"]
    assert "-artifact_prefix=x;echo unsafe/" in cmd
    assert "-max_len=16385" in cmd and "-timeout=5" in cmd and "-rss_limit_mb=512" in cmd


@pytest.fixture
def mocked_engine(monkeypatch):
    monkeypatch.setattr(runner, "platform_check", lambda: None)
    class Process:
        pid = 123456789
        def __init__(self, args, **kwargs):
            assert kwargs["start_new_session"] and "shell" not in kwargs
            kwargs["stdout"].write(self.log)
        log = DONE
        returncode = 0
        def wait(self, timeout=None): return self.returncode
    monkeypatch.setattr(runner.subprocess, "Popen", Process)
    return Process


def test_successful_runner_records_provenance_and_private_outputs(tmp_path, mocked_engine):
    output = tmp_path / "campaign"
    report = runner.run(output, runs=100)
    assert report["status"] == "PASS" and report["executed_units"] == 100
    assert report["preflight"]["profiles"] == 20
    assert report["source_sha256"]["v17_fuzz_targets.py"] == hashlib.sha256((runner.ROOT / "v17_fuzz_targets.py").read_bytes()).hexdigest()
    assert report["native_sanitizers"] is False and report["os_sandbox"] is False
    assert {p.name for p in output.iterdir()} == {"report.json", "engine.log", "failures"}
    assert output.stat().st_mode & 0o777 == 0o700
    for name in ("engine.log", "report.json"):
        assert (output / name).stat().st_mode & 0o777 == 0o600
    assert json.loads((output / "report.json").read_text()) == report


@pytest.mark.parametrize("code,log", [(1, DONE), (-9, DONE), (0, b"partial"), (0, DONE.replace(b"#100", b"#99"))])
def test_runner_never_promotes_failed_or_partial_engine(tmp_path, mocked_engine, code, log):
    mocked_engine.returncode = code
    mocked_engine.log = log
    report = runner.run(tmp_path / "campaign", runs=100)
    assert report["status"] == "FAIL" and report["error_type"] == "RuntimeError"
    assert "executed_units" not in report


def test_parent_timeout_kills_child_and_retains_failure(tmp_path, mocked_engine, monkeypatch):
    calls = []
    def wait(self, timeout=None):
        if timeout is not None: raise subprocess.TimeoutExpired("redacted", timeout)
        return -9
    monkeypatch.setattr(mocked_engine, "wait", wait)
    monkeypatch.setattr(runner.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    report = runner.run(tmp_path / "campaign", runs=100)
    assert report["status"] == "FAIL" and report["error_type"] == "TimeoutExpired"
    assert calls == [(mocked_engine.pid, runner.signal.SIGKILL)]


def test_failed_input_blocks_success_even_with_done(tmp_path, mocked_engine, monkeypatch):
    original = mocked_engine.__init__
    def init(self, args, **kwargs):
        original(self, args, **kwargs)
        prefix = next(arg.split("=", 1)[1] for arg in args if arg.startswith("-artifact_prefix="))
        runner.private_write(Path(prefix) / "crash-synthetic", b"\x00invalid")
    monkeypatch.setattr(mocked_engine, "__init__", init)
    output = tmp_path / "campaign"
    assert runner.run(output, runs=100)["status"] == "FAIL"
    assert (output / "failures/crash-synthetic").read_bytes() == b"\x00invalid"


@pytest.mark.parametrize("existing", ["directory", "file", "symlink"])
def test_existing_destination_never_overwritten(tmp_path, mocked_engine, existing):
    output = tmp_path / "campaign"
    target = tmp_path / "retained"
    target.write_bytes(b"retained")
    if existing == "directory": output.mkdir()
    elif existing == "file": output.write_bytes(b"retained")
    else: output.symlink_to(target)
    with pytest.raises(FileExistsError): runner.run(output, runs=100)
    assert target.read_bytes() == b"retained"


def test_cli_invalid_options_are_redacted_and_create_nothing(tmp_path):
    output = tmp_path / "campaign"
    result = subprocess.run([sys.executable, str(runner.ROOT / "scripts/run_coverage_fuzz_v17.py"),
                             "--runs", "0", "--out-dir", str(output)], capture_output=True)
    assert result.returncode == 1 and not output.exists()
    assert json.loads(result.stdout) == {"status": "FAIL", "error_type": "ValueError"}


@pytest.mark.parametrize("filename", ["ci.yml", "full-regression.yml"])
def test_fuzz_workflow_yaml_and_required_campaign(filename):
    workflow = yaml.safe_load((runner.ROOT / ".github/workflows" / filename).read_text())
    steps = next(iter(workflow["jobs"].values()))["steps"]
    commands = [step["run"] for step in steps if "run" in step]
    assert all(isinstance(command, str) for command in commands)
    assert any("--only-binary=:all: -r requirements-fuzz.txt" in command for command in commands)
    assert any("scripts/run_coverage_fuzz_v17.py --runs " in command for command in commands)
    assert all(step.get("continue-on-error") is not True for step in steps)
