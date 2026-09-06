from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

import v17_policy_sync as scheduling
from case_export_v17 import verify_case
from v17_delivery_identity_selftest import synthetic_client_identity
from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import PolicyDeliveryError, prepare_delivery_bundle
from v17_policy_delivery_selftest import synthetic_https
from v17_policy_distribution import PolicyUpdateError
from v17_policy_governance import initialize_governed_store
from v17_policy_governance_selftest import synthetic_governance
from v17_policy_sync import MAX_CONFIG_BYTES, MAX_JOBS, PolicySyncScheduler, check_sync_config, load_sync_config, validate_sync_config
from v17_policy_sync_selftest import schedule_fixture

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


@pytest.fixture
def fixture(tmp_path):
    case = synthetic_export(tmp_path)
    fixture = synthetic_governance(case, tmp_path / "governed.sqlite")
    fixture["case"] = case
    initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
    fixture["body"] = canonical_json_bytes(prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]]))
    return fixture


@pytest.fixture
def config(fixture, tmp_path):
    value = schedule_fixture(fixture, SimpleNamespace(url="https://publisher.invalid/policy.json", ca_file=tmp_path / "unused-ca"), tmp_path)
    value["jobs"][0]["ca_file"] = None
    return value


def success(*args, **kwargs):
    return {"status": "ACCEPTED", "network_performed": True}


def rejected(*args, **kwargs):
    raise PolicyDeliveryError("policy_delivery_tls", "synthetic failure", network_attempted=True)


def second_job(config, tmp_path):
    second = dict(config["jobs"][0], job_id="second", store=str(tmp_path / "second.sqlite"))
    config["jobs"].append(second)
    return second


def cli(command, path, *extra):
    return subprocess.run([sys.executable, str(ROOT / "checkpoint_sync_v17.py"), command, "--config", str(path), *extra],
                          capture_output=True, text=True, timeout=20, cwd=path.parent)


def write_config(tmp_path, config):
    path = tmp_path / "schedule.json"
    path.write_bytes(canonical_json_bytes(config))
    path.chmod(0o600)
    return path


def test_scheduled_mtls_update_backoff_recovery_and_offline_use(fixture, tmp_path, monkeypatch):
    client = synthetic_client_identity(tmp_path / "client", encrypted=True)
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        config = schedule_fixture(fixture, server, tmp_path, client)
        clock = Clock()
        scheduler = PolicySyncScheduler(config, clock=clock)
        first = scheduler.run_due()[0]
        assert first["status"] == "ACCEPTED" and first["attempt"] == 1 and first["consecutive_failures"] == 0
        assert first["result"]["delivery"]["client_identity"]["certificate_sha256"] == server.requests[0]["client_certificate_sha256"]
        before = fixture["path"].read_bytes()
        assert scheduler.run_due() == [] and len(server.requests) == 1
        bad = json.loads(fixture["body"])
        bad["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
        server.body = canonical_json_bytes(bad)
        for advance, expected_delay in ((30, 30), (30, 60), (60, 120)):
            clock.now += advance
            failed = scheduler.run_due()[0]
            assert failed["status"] == "FAIL" and failed["network_attempted"]
            assert failed["next_attempt_in_seconds"] == expected_delay and fixture["path"].read_bytes() == before
        clock.now += 120
        server.body = fixture["body"]
        good = scheduler.run_due()[0]
        assert good["status"] == "UNCHANGED" and good["consecutive_failures"] == 0 and good["next_attempt_in_seconds"] == 30
        assert fixture["path"].read_bytes() == before
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("offline verification attempted network"))
    case = fixture["case"]
    result = verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"], policy_root_anchor=fixture["anchor"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]


def test_preflight_uses_no_dns_or_http_and_does_not_claim_store_freshness(fixture, config, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("preflight attempted DNS"))
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("preflight attempted network"))
    before = fixture["path"].read_bytes()
    result = check_sync_config(config)
    assert result["status"] == "PASS" and not result["network_performed"]
    assert result["jobs"][0]["local_store_authenticated"] and not result["jobs"][0]["store_freshness_evaluated"]
    assert fixture["path"].read_bytes() == before
    future = datetime.now(timezone.utc) + timedelta(days=10)
    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return future
    monkeypatch.setattr("v17_policy_governance.datetime", Later)
    monkeypatch.setattr("v17_policy_distribution.datetime", Later)
    assert check_sync_config(config)["status"] == "PASS"


@pytest.mark.parametrize("issue,code", [("missing-store", "policy_store_unavailable"), ("anchor-pin", "sync_schedule_anchor_pin_mismatch"), ("bad-ca", "policy_delivery_ca_invalid")])
def test_local_job_failure_is_reported_without_network(fixture, config, tmp_path, monkeypatch, issue, code):
    job = config["jobs"][0]
    if issue == "missing-store":
        job["store"] = str(tmp_path / "absent.sqlite")
    elif issue == "anchor-pin":
        job["anchor_sha256"] = "0" * 64
    else:
        job["ca_file"] = str(tmp_path / "absent-ca.pem")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("local failure attempted DNS"))
    before = fixture["path"].read_bytes()
    checked = check_sync_config(config)
    result = PolicySyncScheduler(config).run_once()
    assert checked["status"] == result["status"] == "FAIL"
    assert checked["jobs"][0]["code"] == result["jobs"][0]["code"] == code
    assert not result["jobs"][0]["network_attempted"] and fixture["path"].read_bytes() == before
    assert not (tmp_path / "absent.sqlite").exists()


def test_explicit_job_floors_still_apply_after_scheduled_download(fixture, tmp_path):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        config = schedule_fixture(fixture, server, tmp_path)
        config["jobs"][0]["minimum_policy_revision"] = 3
        before = fixture["path"].read_bytes()
        result = PolicySyncScheduler(config).run_once()
        assert result["status"] == "FAIL" and result["jobs"][0]["network_attempted"]
        assert fixture["path"].read_bytes() == before


def test_deadline_starts_at_completion_and_missed_intervals_do_not_burst(config, monkeypatch):
    clock, calls = Clock(), []
    def slow(*args, **kwargs):
        calls.append(clock.now)
        clock.now += 50
        return success()
    monkeypatch.setattr(scheduling, "sync_policy", slow)
    scheduler = PolicySyncScheduler(config, clock=clock)
    scheduler.run_due()
    assert scheduler.next_delay() == 30
    clock.now += 29
    assert scheduler.run_due() == []
    clock.now += 10000
    assert len(scheduler.run_due()) == 1 and len(calls) == 2
    assert scheduler.next_delay() == 30


def test_wall_clock_changes_do_not_advance_monotonic_deadlines(config, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(scheduling, "sync_policy", success)
    scheduler = PolicySyncScheduler(config, clock=clock)
    scheduler.run_due()
    class DifferentUTC(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2040, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(scheduling, "datetime", DifferentUTC)
    assert scheduler.run_due() == [] and scheduler.next_delay() == 30
    clock.now += 30
    assert scheduler.run_due()[0]["started_at"].startswith("2040")


def test_failure_backoff_caps_and_success_resets_it(config, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(scheduling, "sync_policy", rejected)
    scheduler = PolicySyncScheduler(config, clock=clock)
    delays = []
    for _ in range(25):
        row = scheduler.run_due()[0]
        delays.append(row["next_attempt_in_seconds"])
        clock.now += row["next_attempt_in_seconds"]
    assert delays[:4] == [30, 60, 120, 120] and max(delays) == 120
    assert row["consecutive_failures"] == 20 and row["attempt"] == 25
    monkeypatch.setattr(scheduling, "sync_policy", success)
    good = scheduler.run_due()[0]
    assert good["consecutive_failures"] == 0 and good["next_attempt_in_seconds"] == 30


@pytest.mark.parametrize("padding", [0, 5, 10])
def test_jitter_respects_configured_bounds_and_backoff_cap(config, monkeypatch, padding):
    config["jobs"][0].update(jitter_seconds=10, max_backoff_seconds=35)
    monkeypatch.setattr(scheduling, "sync_policy", success)
    scheduler = PolicySyncScheduler(config, clock=Clock(), jitter=lambda maximum: padding)
    assert scheduler.run_due()[0]["next_attempt_in_seconds"] == min(35, 30 + padding)


def test_jobs_fail_and_recover_independently_without_disabling_other_jobs(config, tmp_path, monkeypatch):
    second_job(config, tmp_path)
    calls = []
    def outcome(path, *args, **kwargs):
        calls.append(Path(path).name)
        return success() if Path(path).name == "second.sqlite" else rejected()
    monkeypatch.setattr(scheduling, "sync_policy", outcome)
    scheduler = PolicySyncScheduler(config, clock=Clock())
    result = scheduler.run_once()
    assert result["status"] == "FAIL" and [row["status"] for row in result["jobs"]] == ["FAIL", "ACCEPTED"]
    assert len(calls) == 2 and [row["consecutive_failures"] for row in result["jobs"]] == [1, 0]


def test_disabled_jobs_do_not_read_unavailable_inputs_or_make_requests(config, monkeypatch):
    config["jobs"][0].update(enabled=False, anchor="missing-anchor.json", store="missing-store.sqlite")
    monkeypatch.setattr(scheduling, "_settings", lambda *args: pytest.fail("disabled job inspected inputs"))
    scheduler = PolicySyncScheduler(config)
    assert check_sync_config(config)["jobs"][0]["status"] == "DISABLED"
    assert scheduler.next_delay() is None and scheduler.run_once()["disabled_jobs"] == ["synthetic-verifier"]
    stopped = scheduler.watch(lambda row: pytest.fail("disabled job emitted attempt"), stop_event=Event())
    assert stopped["attempts"] == 0


def test_config_is_snapshotted_and_changes_require_explicit_reload(config, monkeypatch):
    seen = []
    monkeypatch.setattr(scheduling, "sync_policy", lambda path, anchor, url, **kwargs: (seen.append(url), success())[1])
    scheduler = PolicySyncScheduler(config)
    config["jobs"][0].update(url="https://another.invalid/policy.json", enabled=False)
    assert scheduler.run_due()[0]["status"] == "ACCEPTED" and seen == ["https://publisher.invalid/policy.json"]


def test_anchor_pin_is_rechecked_before_every_attempt(config, monkeypatch):
    clock = Clock()
    calls = []
    monkeypatch.setattr(scheduling, "sync_policy", lambda *args, **kwargs: (calls.append(True), success())[1])
    scheduler = PolicySyncScheduler(config, clock=clock)
    assert scheduler.run_due()[0]["status"] == "ACCEPTED"
    path = Path(config["jobs"][0]["anchor"])
    root = json.loads(path.read_text())
    root["version"] += 1
    path.write_bytes(canonical_json_bytes(root))
    clock.now += 30
    row = scheduler.run_due()[0]
    assert row["code"] == "sync_schedule_anchor_pin_mismatch" and not row["network_attempted"] and len(calls) == 1


def test_client_files_are_revalidated_on_each_scheduled_attempt(fixture, tmp_path):
    client = synthetic_client_identity(tmp_path / "client", encrypted=True)
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        config = schedule_fixture(fixture, server, tmp_path, client)
        clock = Clock()
        scheduler = PolicySyncScheduler(config, clock=clock)
        assert scheduler.run_due()[0]["status"] == "ACCEPTED"
        before = fixture["path"].read_bytes()
        secret = client["files"]["password.txt"].read_bytes()
        client["files"]["password.txt"].write_bytes(b"invalid-test-password")
        clock.now += 30
        failed = scheduler.run_due()[0]
        assert failed["status"] == "FAIL" and not failed["network_attempted"] and len(server.requests) == 1
        rendered = json.dumps(failed)
        assert str(client["files"]["password.txt"]) not in rendered and secret.strip().decode() not in rendered
        assert fixture["path"].read_bytes() == before


def test_stop_event_prevents_new_jobs_and_interrupts_waiting(config, tmp_path, monkeypatch):
    second_job(config, tmp_path)
    stop = Event()
    calls = []
    def execute(*args, **kwargs):
        calls.append(True)
        stop.set()
        return success()
    monkeypatch.setattr(scheduling, "sync_policy", execute)
    scheduler = PolicySyncScheduler(config)
    emitted = []
    result = scheduler.watch(emitted.append, stop_event=stop)
    assert len(calls) == len(emitted) == result["attempts"] == 1 and result["status"] == "STOPPED"
    assert scheduler.run_due(stop_event=stop) == []


def test_watch_waits_until_due_and_honors_finite_round_limit(config, monkeypatch):
    clock, emitted, waited = Clock(), [], []
    monkeypatch.setattr(scheduling, "sync_policy", success)
    class Stop:
        def is_set(self):
            return False
        def wait(self, delay):
            waited.append(delay)
            clock.now += delay
    result = PolicySyncScheduler(config, clock=clock).watch(emitted.append, stop_event=Stop(), max_rounds=3)
    assert len(emitted) == result["attempts"] == result["rounds"] == 3 and waited == [30, 30]
    assert not result["scheduling_state_persisted"]


def test_overlapping_rounds_are_rejected_and_lock_is_released(config, monkeypatch):
    entered, release = Event(), Event()
    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return success()
    monkeypatch.setattr(scheduling, "sync_policy", blocked)
    scheduler = PolicySyncScheduler(config)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(scheduler.run_due)
        try:
            assert entered.wait(5)
            with pytest.raises(PolicyUpdateError) as error:
                scheduler.run_due()
            assert error.value.code == "sync_schedule_busy"
        finally:
            release.set()
        assert pending.result(timeout=5)[0]["status"] == "ACCEPTED"
    assert scheduler.run_due() == []


def test_watch_emits_each_result_before_next_job_and_stops_on_output_error(config, tmp_path, monkeypatch):
    second_job(config, tmp_path)
    called, emitted = [], []
    monkeypatch.setattr(scheduling, "sync_policy", lambda path, *args, **kwargs: (called.append(path), success())[1])
    scheduler = PolicySyncScheduler(config)
    def failed_output(row):
        emitted.append(row)
        assert len(called) == 1
        raise OSError("synthetic output failure")
    with pytest.raises(OSError):
        scheduler.watch(failed_output, stop_event=Event())
    assert len(emitted) == len(called) == 1
    assert scheduler.run_due()[0]["job_id"] == "second"


def test_restart_discards_timing_state_but_cannot_reset_accepted_policy(fixture, tmp_path):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        config = schedule_fixture(fixture, server, tmp_path)
        first = PolicySyncScheduler(config)
        assert first.run_due()[0]["status"] == "ACCEPTED"
        before = fixture["path"].read_bytes()
        assert first.run_due() == []
        restarted = PolicySyncScheduler(config).run_due()[0]
        assert restarted["status"] == "UNCHANGED" and restarted["attempt"] == 1
        assert fixture["path"].read_bytes() == before


@pytest.mark.parametrize("change", [
    lambda c: c.update(schema="other"), lambda c: c.update(extra=True), lambda c: c.update(jobs=[]),
    lambda c: c.update(jobs={}), lambda c: c.update(jobs=[{}]), lambda c: c.update(jobs=[None]),
    lambda c: c.update(jobs=c["jobs"] * (MAX_JOBS + 1)),
    lambda c: c["jobs"][0].update(command="execute"), lambda c: c["jobs"][0].update(password="inline-secret"),
    lambda c: c["jobs"][0].update(anchor_sha256=None), lambda c: c["jobs"][0].update(anchor_sha256="A" * 64),
    lambda c: c["jobs"][0].update(enabled=1), lambda c: c["jobs"][0].update(job_id="../escape"),
    lambda c: c["jobs"][0].update(job_id="bad\nlog"), lambda c: c["jobs"][0].update(url="http://publisher.invalid"),
    lambda c: c["jobs"][0].update(url="https://user:secret@publisher.invalid"),
    lambda c: c["jobs"][0].update(url="https://publisher.invalid?secret=1"),
    lambda c: c["jobs"][0].update(store=""), lambda c: c["jobs"][0].update(anchor=None),
    lambda c: c["jobs"][0].update(ca_file="bad\x00path"),
    lambda c: c["jobs"][0].update(client_cert_file="cert.pem"),
    lambda c: c["jobs"][0].update(client_key_file="key.pem"),
    lambda c: c["jobs"][0].update(client_key_password_file="password.txt"),
    lambda c: c["jobs"][0].update(expected_client_certificate_sha256="0" * 64),
])
def test_malformed_or_unauthorized_job_fields_reject_entire_configuration(config, change, monkeypatch):
    change(config)
    monkeypatch.setattr(scheduling, "sync_policy", lambda *args, **kwargs: pytest.fail("invalid config executed a job"))
    with pytest.raises((PolicyUpdateError, ValueError)):
        PolicySyncScheduler(config)


@pytest.mark.parametrize("name,value", [
    ("interval_seconds", 29), ("interval_seconds", 86401), ("interval_seconds", True), ("interval_seconds", 30.5),
    ("max_backoff_seconds", 29), ("max_backoff_seconds", 604801), ("max_backoff_seconds", False),
    ("jitter_seconds", -1), ("jitter_seconds", 31), ("jitter_seconds", True),
    ("timeout_seconds", 0), ("timeout_seconds", 61), ("timeout_seconds", "10"),
    ("minimum_policy_revision", 0), ("minimum_root_version", True), ("minimum_root_version", -1),
])
def test_schedule_bounds_and_floors_are_strict(config, name, value):
    config["jobs"][0][name] = value
    with pytest.raises(PolicyUpdateError):
        validate_sync_config(config)


@pytest.mark.parametrize("alias", ["same-id", "same-path", "relative-alias", "hard-link"])
def test_duplicate_ids_or_store_aliases_are_rejected(config, tmp_path, alias):
    second = second_job(config, tmp_path)
    if alias == "same-id":
        second["job_id"] = config["jobs"][0]["job_id"]
    elif alias == "same-path":
        second["store"] = config["jobs"][0]["store"]
    elif alias == "relative-alias":
        second["store"] = str(tmp_path / "nested" / ".." / "governed.sqlite")
    else:
        os.link(config["jobs"][0]["store"], second["store"])
    with pytest.raises(PolicyUpdateError):
        validate_sync_config(config)


def test_all_jobs_validate_before_any_are_started(config, tmp_path, monkeypatch):
    second_job(config, tmp_path)["command"] = "unapproved"
    monkeypatch.setattr(scheduling, "sync_policy", lambda *args, **kwargs: pytest.fail("partially validated config ran"))
    with pytest.raises(PolicyUpdateError):
        PolicySyncScheduler(config).run_once()


def test_config_relative_paths_are_anchored_to_its_directory(config, tmp_path, monkeypatch):
    config["jobs"][0].update(store="governed.sqlite", anchor="approved-anchor.json")
    path = write_config(tmp_path, config)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    normalized = load_sync_config(path)
    assert normalized["jobs"][0]["store"] == str(tmp_path / "governed.sqlite")
    assert check_sync_config(normalized)["status"] == "PASS"
    assert sha256_object(normalized) == PolicySyncScheduler(normalized).config_sha256


@pytest.mark.parametrize("raw", [b"", b"{}", b'{"schema":1,"schema":2}', b'{"schema":NaN}', b"x" * (MAX_CONFIG_BYTES + 1)])
def test_config_file_is_strict_bounded_json(tmp_path, raw):
    path = tmp_path / "schedule.json"
    path.write_bytes(raw)
    with pytest.raises((PolicyUpdateError, ValueError)):
        load_sync_config(path)


def test_configuration_symlinks_are_not_followed(config, tmp_path):
    path = write_config(tmp_path, config)
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    with pytest.raises(PolicyUpdateError):
        load_sync_config(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode enforcement")
@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_configuration_rejects_group_or_other_write_access(config, tmp_path, mode):
    path = write_config(tmp_path, config)
    path.chmod(mode)
    with pytest.raises(PolicyUpdateError) as error:
        load_sync_config(path)
    assert error.value.code == "sync_schedule_file_permissions"


@pytest.mark.parametrize("command", ["check", "once", "watch"])
def test_cli_check_once_and_finite_watch(fixture, tmp_path, command):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        path = write_config(tmp_path, schedule_fixture(fixture, server, tmp_path))
        result = cli(command, path, *( ["--max-rounds", "1"] if command == "watch" else []))
        assert result.returncode == 0, result.stdout + result.stderr
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        if command == "check":
            assert rows[0]["status"] == "PASS" and not server.requests
        elif command == "once":
            assert rows[0]["jobs"][0]["status"] == "ACCEPTED" and len(server.requests) == 1
        else:
            assert rows[0]["status"] == "ACCEPTED" and rows[1]["status"] == "STOPPED" and len(server.requests) == 1


def test_cli_failure_and_watch_shutdown_do_not_claim_sync_success(fixture, tmp_path):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        config = schedule_fixture(fixture, server, tmp_path)
        config["jobs"][0]["anchor_sha256"] = "0" * 64
        path = write_config(tmp_path, config)
        for mode in ("check", "once"):
            result = cli(mode, path)
            assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL"
        watched = cli("watch", path, "--max-rounds", "1")
        rows = [json.loads(line) for line in watched.stdout.splitlines()]
        assert watched.returncode == 0 and rows[0]["status"] == "FAIL" and rows[1]["status"] == "STOPPED"
        assert not server.requests


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe and signal integration")
def test_watch_cli_handles_sigterm_while_waiting(fixture, tmp_path):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        path = write_config(tmp_path, schedule_fixture(fixture, server, tmp_path))
        process = subprocess.Popen([sys.executable, str(ROOT / "checkpoint_sync_v17.py"), "watch", "--config", str(path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(timeout=5), "watch did not emit its first attempt"
            assert json.loads(process.stdout.readline())["status"] == "ACCEPTED"
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 0, stderr
            assert json.loads(stdout)["status"] == "STOPPED" and len(server.requests) == 1
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


@pytest.mark.parametrize("rounds", ["0", "-1", "1000001"])
def test_cli_invalid_round_limits_fail_before_network(fixture, tmp_path, rounds):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        path = write_config(tmp_path, schedule_fixture(fixture, server, tmp_path))
        result = cli("watch", path, "--max-rounds", rounds)
        assert result.returncode == 1 and not server.requests
