"""Real worker limits, two-source bindings, fail-closed replies, and CLI custody."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import representation_differential as legacy
import representation_integrity_analyze as pipeline
import v17_representation_compare as bounded
from v17_representation_compare_selftest import MACHINE, VISIBLE, check

ROOT = Path(bounded.__file__).resolve().parent


def result(machine=MACHINE, visible=VISIBLE):
    report = legacy.analyze(machine.decode(), visible.decode())
    report["intake"] = bounded.intake(machine, visible, True)
    return report


def unavailable(report):
    assert report["intake"]["analysis_available"] is False
    assert report["findings"] == [{"type": "representation_comparison_incomplete", "severity": "high"}]
    assert "token_similarity" not in report and "character_similarity" not in report
    assert report["intake"]["collection_complete"] is None
    assert all(report["intake"][key] is False for key in bounded.FALSE_FLAGS)


@pytest.mark.skipif(sys.platform != "linux", reason="qualified Linux worker")
@pytest.mark.parametrize("machine,visible", [(MACHINE, VISIBLE), (MACHINE, MACHINE), (b"", b""),
    (b"", VISIBLE), ("é a\r\nb\t".encode(), "e\u0301 a b".encode()), (b" " * 16384, b" " * 16384)])
def test_real_worker_preserves_legacy_scores_findings_and_raw_sources(machine, visible):
    report = bounded.compare(machine, visible)
    assert report == result(machine, visible)
    assert report["intake"]["machine_size_bytes"] == len(machine)
    assert report["intake"]["visible_size_bytes"] == len(visible)
    assert all(report["intake"][key] is False for key in bounded.FALSE_FLAGS)


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("raw", [None, "text", [], bytearray(b"a"), memoryview(b"a"), b"\xff", b"x" * 16385])
def test_bad_source_never_launches_worker(monkeypatch, side, raw):
    monkeypatch.setattr(bounded.subprocess, "Popen", lambda *a, **kw: pytest.fail("worker launched"))
    pair = [MACHINE, VISIBLE]; pair[side] = raw
    report = bounded.compare(*pair); unavailable(report)
    if raw == b"\xff": assert report["intake"]["machine_source_sha256"] == bounded.sha256_bytes(pair[0])


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b"null", b"{}", b"x" * (bounded.INPUT_BYTES + 1),
    b'{"schema":"x","machine":"","visible":""}',
    b'{"schema":"x","schema":"x","machine":"","visible":""}'])
def test_worker_rejects_invalid_protocol_before_comparison(raw):
    with pytest.raises(ValueError): bounded.decode_request(raw)


@pytest.mark.parametrize("key,value", [("machine", None), ("visible", []), ("machine", "!"),
    ("visible", "QR=="), ("machine", "QQ==\n"), ("visible", "x" * 21849), ("visible", "/w=="),
    ("schema", "other"), ("extra", True)])
def test_worker_request_shape_and_canonical_encoding(key, value):
    obj = json.loads(bounded.request(MACHINE, VISIBLE)); obj[key] = value
    with pytest.raises(ValueError): bounded.decode_request(json.dumps(obj).encode())


@pytest.fixture
def process(monkeypatch):
    class Process:
        pid = 123456789
        returncode = 0
        output = json.dumps(result()).encode()
        def __init__(self, args, **kwargs):
            assert args == [sys.executable, str(bounded.WORKER)]
            assert kwargs["start_new_session"] and "shell" not in kwargs
        def communicate(self, raw=None, timeout=None):
            if raw is not None:
                assert bounded.decode_request(raw) == (MACHINE, VISIBLE)
                assert timeout == bounded.WALL_SECONDS
            return self.output, None
    monkeypatch.setattr(bounded.subprocess, "Popen", Process)
    return Process


@pytest.mark.parametrize("path,value", [
    (("schema",), "other"), (("machine_text_sha256",), "0" * 64), (("visible_text_sha256",), "0" * 64),
    (("machine_source",), "forged"), (("visible_source",), "forged"), (("machine_chars",), True),
    (("visible_chars",), 0), (("token_similarity",), True), (("character_similarity",), -0.1),
    (("token_similarity",), 1.1), (("character_similarity",), float("inf")), (("token_similarity",), float("nan")),
    (("findings",), [] + [{"type": "arbitrary", "severity": "low"}]), (("rule",), "x" * 257),
    (("extra",), True), (("intake", "schema"), "other"), (("intake", "analysis_available"), 1),
    (("intake", "machine_source_sha256"), "0" * 64), (("intake", "visible_source_sha256"), "0" * 64),
    (("intake", "machine_size_bytes"), 0), (("intake", "visible_size_bytes"), True),
    (("intake", "source_authenticity_verified"), True), (("intake", "independent_rendering_verified"), True),
    (("intake", "network_required"), 0), (("intake", "collection_complete"), True)])
def test_forged_child_reply_is_unknown(process, path, value):
    report = result(); target = report
    for key in path[:-1]: target = target[key]
    target[path[-1]] = value; process.output = json.dumps(report).encode()
    unavailable(bounded.compare(MACHINE, VISIBLE))


@pytest.mark.parametrize("key", ["intake", "findings", "machine_text_sha256", "visible_chars", "collection_complete"])
def test_missing_child_fields_are_unknown(process, key):
    report = result()
    del (report["intake"] if key == "collection_complete" else report)[key]
    process.output = json.dumps(report).encode(); unavailable(bounded.compare(MACHINE, VISIBLE))


@pytest.mark.parametrize("raw", [b"", b"{", b"null", b"x" * (bounded.OUTPUT_BYTES + 1),
    json.dumps(result()).encode().replace(b'"schema":', b'"schema": "duplicate", "schema":', 1)])
def test_bad_or_excessive_child_json_is_unknown(process, raw):
    process.output = raw; unavailable(bounded.compare(MACHINE, VISIBLE))


@pytest.mark.parametrize("value", [None, True, -1, 2, float("nan"), float("inf"), 10**1000])
def test_similarity_scalars_are_bounded_real_numbers(value):
    assert not bounded.score(value)


@pytest.mark.parametrize("code", [1, -9, -24])
def test_failed_or_resource_killed_child_cannot_be_success(process, code):
    process.returncode = code; unavailable(bounded.compare(MACHINE, VISIBLE))


@pytest.mark.parametrize("interrupt", [False, True])
def test_timeout_and_interrupt_kill_process_group(process, monkeypatch, interrupt):
    calls = []
    def communicate(self, raw=None, timeout=None):
        if timeout is not None:
            if interrupt: raise KeyboardInterrupt
            raise subprocess.TimeoutExpired("redacted", timeout)
        return b"", None
    monkeypatch.setattr(process, "communicate", communicate)
    monkeypatch.setattr(bounded.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    if interrupt:
        with pytest.raises(KeyboardInterrupt): bounded.compare(MACHINE, VISIBLE)
    else: unavailable(bounded.compare(MACHINE, VISIBLE))
    assert calls == [(process.pid, bounded.signal.SIGKILL)]


def test_unqualified_platform_is_explicit_unknown(monkeypatch):
    monkeypatch.setattr(bounded.sys, "platform", "darwin")
    monkeypatch.setattr(bounded.subprocess, "Popen", lambda *a, **kw: pytest.fail("worker launched"))
    unavailable(bounded.compare(MACHINE, VISIBLE))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux limits and guards")
def test_actual_child_enforces_limits_and_python_network_process_tripwires():
    code = '''import os, resource, runpy, socket, subprocess
import representation_differential as d
original = d.analyze
def probe(*args):
    assert resource.getrlimit(resource.RLIMIT_CPU) == (3, 3)
    assert resource.getrlimit(resource.RLIMIT_AS) == (256*1024**2, 256*1024**2)
    assert resource.getrlimit(resource.RLIMIT_FSIZE) == (0, 0)
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    for action in (lambda: socket.getaddrinfo('invalid.example', 443), lambda: subprocess.Popen(['invalid']), lambda: os.system('invalid')):
        try: action()
        except RuntimeError: pass
        else: raise AssertionError('tripwire missing')
    return original(*args)
d.analyze = probe
runpy.run_path('scripts/representation_compare_worker_v17.py', run_name='__main__')
'''
    completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, input=bounded.request(MACHINE, VISIBLE),
                               capture_output=True, timeout=10)
    assert completed.returncode == 0 and json.loads(completed.stdout) == result()


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversize", "missing", "directory"])
def test_each_file_requires_a_bounded_regular_snapshot(tmp_path, monkeypatch, side, kind):
    pair = [tmp_path / "machine", tmp_path / "visible"]
    pair[1 - side].write_bytes(MACHINE)
    path = pair[side]
    if kind == "symlink": path.symlink_to(pair[1 - side])
    elif kind == "fifo": os.mkfifo(path)
    elif kind == "oversize": path.write_bytes(b"x" * 16385)
    elif kind == "directory": path.mkdir()
    monkeypatch.setattr(bounded, "compare", lambda *a: pytest.fail("comparison called"))
    with pytest.raises((ValueError, OSError)): bounded.compare_files(*pair)


def test_snapshots_are_passed_once_and_source_labels_do_not_enter_worker(tmp_path, monkeypatch):
    machine, visible = tmp_path / "machine", tmp_path / "visible"
    machine.write_bytes(MACHINE); visible.write_bytes(VISIBLE)
    def compare(first, second):
        machine.write_bytes(b"changed"); visible.write_bytes(b"changed")
        assert (first, second) == (MACHINE, VISIBLE)
        return result(first, second)
    monkeypatch.setattr(bounded, "compare", compare)
    report = bounded.compare_files(machine, visible, source_machine="parser observation", source_visible="supplied observation")
    assert report["machine_source"] == "parser observation" and report["visible_source"] == "supplied observation"
    assert report["intake"]["machine_source_sha256"] == bounded.sha256_bytes(MACHINE)


@pytest.mark.parametrize("label", [[], 1, "x" * 4097])
def test_source_labels_are_bounded_before_file_reads(label, monkeypatch):
    monkeypatch.setattr(bounded, "read_snapshot", lambda *a: pytest.fail("file read"))
    with pytest.raises(ValueError): bounded.compare_files("machine", "visible", source_visible=label)


def cli(tmp_path, *, output=None, extra=(), machine=MACHINE, visible=VISIBLE):
    first, second = tmp_path / "machine.txt", tmp_path / "visible.txt"
    first.write_bytes(machine); second.write_bytes(visible)
    args = [sys.executable, str(ROOT / "representation_differential.py"), "--machine", str(first), "--visible", str(second), *extra]
    if output is not None: args += ["--out", str(output)]
    return subprocess.run(args, cwd=ROOT, capture_output=True, timeout=10)


@pytest.mark.skipif(sys.platform != "linux", reason="qualified worker")
def test_cli_private_report_preserves_critical_findings_and_no_rendering_claim(tmp_path):
    path = tmp_path / "report.json"; completed = cli(tmp_path, output=path)
    assert completed.returncode == 0
    report = json.loads(path.read_text())
    assert report["findings"][0]["severity"] == "critical"
    assert report["intake"]["independent_rendering_verified"] is False
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind", ["file", "symlink", "machine", "visible"])
def test_cli_never_overwrites_report_or_evidence(tmp_path, kind):
    output = tmp_path / (kind + ".txt" if kind in {"machine", "visible"} else "report.json")
    retained = tmp_path / "retained"; retained.write_bytes(b"retained")
    if kind == "file": output.write_bytes(b"retained")
    elif kind == "symlink": output.symlink_to(retained)
    completed = cli(tmp_path, output=output)
    assert completed.returncode == 1 and json.loads(completed.stdout)["status"] == "FAIL"
    assert retained.read_bytes() == b"retained"
    assert (tmp_path / "machine.txt").read_bytes() == MACHINE and (tmp_path / "visible.txt").read_bytes() == VISIBLE
    if kind == "file": assert output.read_bytes() == b"retained"


def test_invalid_utf8_cli_has_bound_sources_and_explicit_unknown(tmp_path):
    completed = cli(tmp_path, machine=b"\xff")
    assert completed.returncode == 1
    report = json.loads(completed.stdout); unavailable(report)
    assert report["intake"]["machine_source_sha256"] == bounded.sha256_bytes(b"\xff")


def test_excessive_formatted_output_creates_nothing(tmp_path):
    output = tmp_path / "report.json"
    completed = cli(tmp_path, output=output, extra=("--machine-source", "😀" * 4096, "--visible-source", "😀" * 4096))
    assert completed.returncode == 1 and not output.exists()


@pytest.mark.parametrize("available", [True, False])
def test_case_pipeline_uses_bounded_comparison_and_reports_unavailability(tmp_path, monkeypatch, capsys, available):
    report = result() if available else {"schema": bounded.RESULT_SCHEMA,
        "intake": bounded.intake(MACHINE, VISIBLE, False),
        "findings": [{"type": "representation_comparison_incomplete", "severity": "high"}]}
    calls = []
    def compare(first, second): calls.append((first, second)); return copy.deepcopy(report)
    monkeypatch.setattr(pipeline, "representation_diff", compare)
    case = tmp_path / "case"
    monkeypatch.setattr(sys, "argv", ["pipeline", "--case", str(case), "--machine-text", "machine", "--visible-text", "visible"])
    if available: pipeline.main()
    else:
        with pytest.raises(SystemExit) as error: pipeline.main()
        assert error.value.code == 1
    assert calls == [("machine", "visible")]
    saved = case / "representation_differential.json"
    assert json.loads(saved.read_text()) == report and saved.stat().st_mode & 0o777 == 0o600
    run = json.loads((case / "representation_integrity_run.json").read_text())
    assert run["review_required"] is (not available) and run["representation_comparison_available"] is available
    if available:
        assert "human_machine_representation_divergence" in run["signals"] and run["attached_packs"]
    assert json.loads(capsys.readouterr().out) == run


def test_case_pipeline_requires_both_sources_before_creating_case(tmp_path, monkeypatch):
    case = tmp_path / "case"
    monkeypatch.setattr(sys, "argv", ["pipeline", "--case", str(case), "--machine-text", "machine"])
    with pytest.raises(SystemExit) as error: pipeline.main()
    assert error.value.code == 2 and not case.exists()


def test_case_comparison_preserves_prior_report(tmp_path, monkeypatch):
    case = tmp_path / "case"; case.mkdir()
    prior = case / "representation_differential.json"; prior.write_bytes(b"retained")
    monkeypatch.setattr(sys, "argv", ["pipeline", "--case", str(case), "--machine-text", "machine", "--visible-text", "visible"])
    monkeypatch.setattr(pipeline, "representation_diff", lambda *a: result())
    with pytest.raises(FileExistsError): pipeline.main()
    assert prior.read_bytes() == b"retained" and not (case / "incident_profile.json").exists()


def test_actual_selftest():
    report = check()
    assert report["status"] == "PASS" and report["valid_pairs"] == 2 and report["invalid_pairs_rejected"] == 2
