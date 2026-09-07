"""Acceptance and fault injection for the bounded synthetic parser campaign."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

import parser_corpus_v17 as cli
import v17_parser_corpus as corpus
from v17_integrity import sha256_bytes

NAMES = tuple(item.name for item in corpus.profiles())


@pytest.mark.parametrize("name", NAMES)
def test_each_fixed_profile_rejects_hostile_inputs_and_replays_accepted_results(name):
    report = corpus.run_campaign(selected=[name], mutations=64)
    assert report["status"] == "PASS" and report["failure_count"] == 0
    assert report["profile_count"] == 1 and report["case_count"] == (90 if name == "cloudtrail-lookup" else 84)
    counts = report["profiles"][0]["outcomes"]
    assert counts["ACCEPT"] >= 2 and counts["REJECT"] >= 18
    assert counts["CRASH"] == counts["INVARIANT_FAILURE"] == 0
    assert report["network_blocked"] and report["process_creation_blocked"]
    assert not report["exhaustive"] and not report["coverage_guided"] and not report["user_corpus_loaded"]


@pytest.mark.parametrize("name", NAMES)
def test_corpus_generation_is_repeatable_bounded_and_contains_seed(name):
    profile = next(item for item in corpus.profiles() if item.name == name)
    first = list(corpus.cases(profile, seed=1234, mutations=32))
    assert first == list(corpus.cases(profile, seed=1234, mutations=32))
    assert first != list(corpus.cases(profile, seed=1235, mutations=32))
    assert first[0].raw == profile.seed and first[0].expectation == "ACCEPT"
    assert all(len(item.raw) <= corpus.MAX_CASE_BYTES for item in first)
    assert {item.category for item in first} >= {"seed", "whitespace", "encoding", "truncation", "depth", "duplicate-key", "invalid-leaf", "structure"}


def test_numeric_mutations_preserve_unmodified_original_tokens():
    raw = b'{"n":9223372036854775807,"d":0.1234567890123456789012345678,"r":1.00000000000000001,"s":"9007199254740993"}'
    value = json.loads(raw, parse_int=corpus._Literal, parse_float=corpus._Literal)
    assert corpus._raw(value) == raw
    changed = corpus._replace(value, ("s",), "different")
    assert corpus._raw(changed) == raw.replace(b'"9007199254740993"', b'"different"')
    assert corpus._raw(value) == raw


@pytest.mark.parametrize("option,value", [("seed", True), ("seed", -1), ("seed", 4294967296), ("seed", "17"), ("seed", None),
                                          ("mutations", True), ("mutations", 0), ("mutations", 2049), ("mutations", 1.0), ("mutations", "10")])
def test_invalid_campaign_bounds_are_rejected(option, value):
    with pytest.raises(ValueError): corpus.run_campaign(**{option: value})


@pytest.mark.parametrize("selected", [[], "cloudtrail-records", [None], ["unknown"], ["cloudtrail-records"] * 2,
                                     ["cloudtrail-records"] * 13, ["../module.py"]])
def test_profile_selection_cannot_load_unknown_or_duplicate_parsers(selected):
    with pytest.raises(ValueError): corpus.run_campaign(selected=selected, mutations=1)


def test_selected_profiles_keep_fixed_order_and_independent_streams():
    selected = ["lossless-tables", "cloudtrail-records"]
    a = corpus.run_campaign(selected=selected, seed=7, mutations=8)
    b = corpus.run_campaign(selected=list(reversed(selected)), seed=7, mutations=8)
    assert a == b and [row["profile"] for row in a["profiles"]] == list(reversed(selected))
    for row in a["profiles"]:
        single = corpus.run_campaign(selected=[row["profile"]], seed=7, mutations=8)
        assert single["profiles"][0] == row


def test_maximum_mutation_count_is_bounded():
    profile = corpus.profiles()[0]
    assert len(list(corpus.cases(profile, seed=4294967295, mutations=2048))) == 2068
    with pytest.raises(ValueError): corpus.Case("invalid", b"x" * (corpus.MAX_CASE_BYTES + 1))
    with pytest.raises(ValueError): corpus.Case("invalid", "text")
    with pytest.raises(ValueError): corpus.Case("invalid", b"raw", "IGNORED")


def fake_profile(monkeypatch, *, normalize=None, compare=None, max_output=10000, expected="ACCEPT", count=1):
    def projection(raw):
        return {"source_sha256": sha256_bytes(raw), "source_authenticity_verified": False,
                "collection_complete": None, "network_required": False}
    def replay(raw, output):
        return {"status": "PASS" if json.loads(output)["source_sha256"] == sha256_bytes(raw) else "FAIL"}
    profile = SimpleNamespace(name="synthetic-fault", seed=b"{}", response=None,
                              module=SimpleNamespace(MAX_OUTPUT_BYTES=max_output),
                              normalize=normalize or projection, compare=compare or replay)
    monkeypatch.setattr(corpus, "profiles", lambda: (profile,))
    monkeypatch.setattr(corpus, "cases", lambda *args, **kwargs: iter([corpus.Case("seed", b"{}", expected)] * count))
    return profile, projection


@pytest.mark.parametrize("mode", ["crash", "wrong-kind", "source", "authority", "network", "complete", "oversized",
                                   "matching-replay", "altered-replay", "nondeterministic", "reject-seed", "accept-malformed",
                                   "request_scope_verified", "query_execution_verified", "query_reexecuted", "permissions_verified", "pagination_chain_verified"])
def test_oracle_detects_injected_parser_regressions(monkeypatch, mode):
    profile, projection = fake_profile(monkeypatch)
    def normalize(raw):
        if mode == "crash": raise RuntimeError("SYNTHETIC-PRIVATE-ERROR")
        if mode == "reject-seed": raise ValueError("SYNTHETIC-PRIVATE-ERROR")
        if mode == "wrong-kind": return []
        value = projection(raw)
        if mode == "source": value["source_sha256"] = "f" * 64
        if mode == "authority": value["source_authenticity_verified"] = True
        if mode == "network": value["network_required"] = True
        if mode == "complete": value["collection_complete"] = True
        if mode.endswith("_verified") or mode == "query_reexecuted": value[mode] = True
        return value
    profile.normalize = normalize
    if mode == "oversized": profile.module.MAX_OUTPUT_BYTES = 10
    if mode == "matching-replay": profile.compare = lambda *args: {"status": "FAIL"}
    if mode == "altered-replay": profile.compare = lambda *args: {"status": "PASS"}
    if mode == "nondeterministic":
        counter = [0]
        def changing(raw):
            counter[0] += 1
            return dict(projection(raw), changing=counter[0])
        profile.normalize = changing
    if mode == "accept-malformed":
        monkeypatch.setattr(corpus, "cases", lambda *args, **kwargs: iter([corpus.Case("encoding", b"{}", "REJECT")]))
    report = corpus.run_campaign(mutations=1)
    assert report["status"] == "FAIL" and report["failure_count"] == 1
    assert "SYNTHETIC-PRIVATE-ERROR" not in json.dumps(report)
    if mode == "nondeterministic": assert report["failures"][0]["reason"] == "NONDETERMINISTIC"
    if mode == "crash": assert report["failures"][0]["error_type"] == "RuntimeError"


@pytest.mark.parametrize("action", ["connect", "connect_ex", "sendto", "dns", "connection", "process", "shell"])
def test_external_action_guards_block_and_restore_python_operations(monkeypatch, action):
    originals = (socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto, socket.getaddrinfo,
                 socket.create_connection, subprocess.Popen, os.system)
    def attempted(raw):
        if action == "dns": socket.getaddrinfo("example.invalid", 443)
        elif action == "connection": socket.create_connection(("192.0.2.1", 443))
        elif action == "process": subprocess.Popen(["never-executed"])
        elif action == "shell": os.system("never-executed")
        else:
            with socket.socket() as sock:
                if action == "sendto": sock.sendto(b"synthetic", ("192.0.2.1", 9))
                else: getattr(sock, action)(("192.0.2.1", 443))
    fake_profile(monkeypatch, normalize=attempted)
    report = corpus.run_campaign(mutations=1)
    assert report["status"] == "FAIL" and report["failures"][0]["error_type"] == "AssertionError"
    assert originals == (socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto, socket.getaddrinfo,
                         socket.create_connection, subprocess.Popen, os.system)


def test_failure_report_is_bounded_and_does_not_include_input_or_error_text(monkeypatch):
    def fail(raw): raise RuntimeError("PRIVATE-SYNTHETIC-CONTENT")
    fake_profile(monkeypatch, normalize=fail, count=35)
    report = corpus.run_campaign(mutations=1)
    assert report["failure_count"] == 35 and len(report["failures"]) == 20 and report["failure_details_truncated"]
    assert "PRIVATE-SYNTHETIC-CONTENT" not in json.dumps(report)
    assert all("raw" not in row and "input_sha256" in row for row in report["failures"])


def test_keyboard_interrupt_is_not_swallowed_and_guards_are_restored(monkeypatch):
    original = socket.socket.connect
    def interrupt(raw): raise KeyboardInterrupt()
    fake_profile(monkeypatch, normalize=interrupt)
    with pytest.raises(KeyboardInterrupt): corpus.run_campaign(mutations=1)
    assert socket.socket.connect is original


def call_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["parser_corpus_v17.py", *map(str, args)])
    code = cli.main(); captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


def test_cli_writes_private_report_and_preserves_existing_output(tmp_path, monkeypatch, capsys):
    output = tmp_path / "report.json"
    args = ("--profile", "lossless-tables", "--mutations", 4, "--seed", 19, "--out", output)
    code, report = call_cli(monkeypatch, capsys, *args)
    assert code == 0 and json.loads(output.read_bytes()) == report
    assert report["case_count"] == 24 and not report["network_performed"]
    before = output.read_bytes()
    code, failed = call_cli(monkeypatch, capsys, *args)
    assert code == 1 and failed["status"] == "FAIL" and output.read_bytes() == before
    if os.name == "posix": assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("mode", ["bad-options", "symlink-output", "interrupt", "campaign-failure", "write-failure"])
def test_cli_failure_and_interrupt_states(tmp_path, monkeypatch, capsys, mode):
    output = tmp_path / "report.json"; args = ["--profile", "cloudtrail-records", "--mutations", 1, "--out", output]
    if mode == "bad-options": args[3] = 0
    if mode == "symlink-output":
        target = tmp_path / "original"; target.write_bytes(b"RETAIN"); output.symlink_to(target)
    if mode == "interrupt":
        def interrupt(**kwargs): raise KeyboardInterrupt()
        monkeypatch.setattr(cli, "run_campaign", interrupt)
    if mode == "campaign-failure": monkeypatch.setattr(cli, "run_campaign", lambda **kwargs: {"status": "FAIL", "failure_count": 1})
    if mode == "write-failure":
        def fail(*args): raise OSError("PRIVATE-PATH")
        monkeypatch.setattr(cli.os, "fsync", fail)
    code, report = call_cli(monkeypatch, capsys, *args)
    assert code == (130 if mode == "interrupt" else 1)
    assert "PRIVATE-PATH" not in json.dumps(report)
    if mode == "symlink-output": assert target.read_bytes() == b"RETAIN"
    if mode in {"bad-options", "interrupt"}: assert not output.exists()
