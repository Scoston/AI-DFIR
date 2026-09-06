"""Explicit scheduling of independently anchored policy synchronization jobs.

Configuration is operator authority, never downloaded metadata. Scheduling
state is process-local; accepted root/policy state remains in governed stores.
"""
from __future__ import annotations

import os
import re
import secrets
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock
from typing import Any

from v17_integrity import sha256_object
from v17_policy_delivery import PolicyDeliveryError, _endpoint, _prepare_sync, _timeout, sync_policy
from v17_policy_distribution import PolicyUpdateError, _HEX, _json, _require, _snapshot
from v17_policy_governance import _floor, load_root

CONFIG_SCHEMA = "ai-dfir/policy-sync-schedule/v1.7"
ATTEMPT_SCHEMA = "ai-dfir/policy-sync-attempt/v1.7"
REPORT_SCHEMA = "ai-dfir/policy-sync-run/v1.7"
MAX_CONFIG_BYTES = 128 * 1024
MAX_JOBS = 32
MAX_BACKOFF_SECONDS = 7 * 86400
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_REQUIRED = {"job_id", "store", "anchor", "anchor_sha256", "url"}
_PATHS = {"store", "anchor", "ca_file", "client_cert_file", "client_key_file", "client_key_password_file"}
_OPTIONAL = {"enabled", "interval_seconds", "max_backoff_seconds", "jitter_seconds", "timeout_seconds",
             "minimum_policy_revision", "minimum_root_version", "expected_client_certificate_sha256"} | (_PATHS - {"store", "anchor"})


def _integer(value, minimum, maximum, label):
    _require(type(value) is int and minimum <= value <= maximum,
             "sync_schedule_interval_invalid", f"invalid {label}")
    return value


def _path(value, base: Path) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 4096 and value.strip() == value
             and not any(ord(char) < 32 or ord(char) == 127 for char in value),
             "sync_schedule_path_invalid", "a nonempty local path without controls is required")
    path = Path(value)
    return str((path if path.is_absolute() else base / path).absolute())


def validate_sync_config(value: Any, *, base_dir: str | Path | None = None) -> dict:
    config = _snapshot(value, MAX_CONFIG_BYTES)
    _require(isinstance(config, dict) and set(config) == {"schema", "jobs"} and config["schema"] == CONFIG_SCHEMA,
             "sync_schedule_config_invalid", "invalid schedule fields or schema")
    _require(isinstance(config["jobs"], list) and 1 <= len(config["jobs"]) <= MAX_JOBS,
             "sync_schedule_jobs_invalid", "schedule must contain one through 32 jobs")
    base = Path(base_dir).absolute() if base_dir is not None else Path.cwd()
    ids, stores, inodes = set(), set(), set()
    for job in config["jobs"]:
        _require(isinstance(job, dict) and _REQUIRED.issubset(job) and set(job).issubset(_REQUIRED | _OPTIONAL),
                 "sync_schedule_job_invalid", "invalid job fields; arbitrary commands and inline credentials are unsupported")
        ident = job["job_id"]
        _require(isinstance(ident, str) and _ID.fullmatch(ident) is not None and ident not in ids,
                 "sync_schedule_job_id_invalid", "job identifiers must be unique safe text")
        ids.add(ident)
        _require(isinstance(job["anchor_sha256"], str) and _HEX.fullmatch(job["anchor_sha256"]) is not None,
                 "sync_schedule_anchor_pin_invalid", "an independent root anchor SHA-256 pin is required")
        _endpoint(job["url"])
        for name in _PATHS:
            value = job.get(name)
            _require(value is not None or name not in {"store", "anchor"}, "sync_schedule_path_invalid", "store and anchor paths required")
            job[name] = _path(value, base) if value is not None else None
        target = Path(job["store"])
        canonical = os.path.normcase(str(target.resolve()))
        _require(canonical not in stores, "sync_schedule_duplicate_store", "jobs cannot target the same store")
        stores.add(canonical)
        if target.exists():
            info = target.stat()
            inode = (info.st_dev, info.st_ino)
            _require(inode not in inodes, "sync_schedule_duplicate_store", "jobs cannot target hard-linked store aliases")
            inodes.add(inode)
        job["enabled"] = job.get("enabled", True)
        _require(type(job["enabled"]) is bool, "sync_schedule_enabled_invalid", "enabled must be boolean")
        interval = _integer(job.get("interval_seconds", 300), 30, 86400, "interval_seconds")
        job["interval_seconds"] = interval
        job["max_backoff_seconds"] = _integer(job.get("max_backoff_seconds", max(3600, interval)), interval, MAX_BACKOFF_SECONDS, "max_backoff_seconds")
        job["jitter_seconds"] = _integer(job.get("jitter_seconds", min(30, interval)), 0, interval, "jitter_seconds")
        job["timeout_seconds"] = _timeout(job.get("timeout_seconds", 10))
        for name, label in (("minimum_policy_revision", "policy revision"), ("minimum_root_version", "root version")):
            job[name] = job.get(name)
            _floor(job[name], 2**53 - 1, label)
        pin = job.get("expected_client_certificate_sha256")
        _require(pin is None or (isinstance(pin, str) and _HEX.fullmatch(pin) is not None),
                 "delivery_identity_pin_invalid", "client leaf pin must be lowercase SHA-256")
        job["expected_client_certificate_sha256"] = pin
        cert, key = job["client_cert_file"], job["client_key_file"]
        _require((cert is None) == (key is None) and (cert is not None or (job["client_key_password_file"] is None and pin is None)),
                 "delivery_identity_required", "client certificate and key must be configured together")
    return _snapshot(config, MAX_CONFIG_BYTES)


def load_sync_config(path: str | Path) -> dict:
    path = Path(path)
    _require(not path.is_symlink() and path.is_file(), "sync_schedule_file_invalid", "regular schedule configuration file required")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_CONFIG_BYTES,
                 "sync_schedule_file_invalid", "schedule file is empty, oversized, or not regular")
        if os.name == "posix":
            _require(info.st_uid in {0, os.geteuid()} and stat.S_IMODE(info.st_mode) & 0o022 == 0,
                     "sync_schedule_file_permissions", "schedule file must have a trusted owner and no group/other write access")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    return validate_sync_config(_json(raw, MAX_CONFIG_BYTES), base_dir=path.absolute().parent)


def _settings(job: dict) -> tuple[dict, dict]:
    anchor = load_root(job["anchor"])
    _require(sha256_object(anchor) == job["anchor_sha256"], "sync_schedule_anchor_pin_mismatch", "root anchor differs from the approved schedule pin")
    settings = {name: job[name] for name in ("ca_file", "client_cert_file", "client_key_file", "client_key_password_file", "expected_client_certificate_sha256")}
    settings.update(timeout=job["timeout_seconds"], minimum_revision=job["minimum_policy_revision"], minimum_root_version=job["minimum_root_version"])
    return anchor, settings


def check_sync_config(config: Any, *, base_dir=None) -> dict:
    config = validate_sync_config(config, base_dir=base_dir)
    rows = []
    for job in config["jobs"]:
        row = {"job_id": job["job_id"], "status": "DISABLED", "network_attempted": False}
        if job["enabled"]:
            try:
                anchor, settings = _settings(job)
                prepared = _prepare_sync(job["store"], anchor, job["url"], **settings)
                row.update(status="CHECKED", local_store_authenticated=True, store_freshness_evaluated=False,
                           client_identity=prepared["identity"])
            except PolicyUpdateError as exc:
                row.update(status="FAIL", code=exc.code)
            except (OSError, ValueError, TypeError):
                row.update(status="FAIL", code="sync_schedule_preflight_failed")
        rows.append(row)
    return {"schema": REPORT_SCHEMA, "mode": "check", "status": "FAIL" if any(row["status"] == "FAIL" for row in rows) else "PASS",
            "config_sha256": sha256_object(config), "network_performed": False, "jobs": rows}


class PolicySyncScheduler:
    """Sequential jobs, monotonic completion-based deadlines, and bounded backoff."""

    def __init__(self, config: Any, *, base_dir=None, clock=None, jitter=None):
        self._config = validate_sync_config(config, base_dir=base_dir)
        self.config_sha256 = sha256_object(self._config)
        self._clock = clock or time.monotonic
        self._jitter = jitter or (lambda maximum: secrets.randbelow(maximum + 1))
        now = self._clock()
        self._state = {job["job_id"]: {"next_due": now, "failures": 0, "attempts": 0} for job in self._config["jobs"]}
        self._lock = Lock()

    def run_due(self, *, stop_event: Event | None = None, emit=None) -> list[dict]:
        _require(self._lock.acquire(blocking=False), "sync_schedule_busy", "a scheduling round is already running")
        try:
            rows = []
            for job in self._config["jobs"]:
                if stop_event is not None and stop_event.is_set():
                    break
                state = self._state[job["job_id"]]
                if not job["enabled"] or self._clock() < state["next_due"]:
                    continue
                padding = self._jitter(job["jitter_seconds"])
                _require(type(padding) is int and 0 <= padding <= job["jitter_seconds"], "sync_schedule_jitter_invalid", "invalid scheduling jitter")
                row = {"schema": ATTEMPT_SCHEMA, "job_id": job["job_id"], "config_sha256": self.config_sha256,
                       "status": "FAIL", "network_attempted": False, "result": None,
                       "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
                try:
                    anchor, settings = _settings(job)
                    result = sync_policy(job["store"], anchor, job["url"], **settings)
                    _require(result.get("status") in {"ACCEPTED", "UNCHANGED"}, "sync_schedule_result_invalid", "unexpected synchronization result")
                    row.update(status=result["status"], network_attempted=result["network_performed"], result=result)
                except PolicyDeliveryError as exc:
                    row.update(code=exc.code, network_attempted=exc.network_attempted)
                except PolicyUpdateError as exc:
                    row["code"] = exc.code
                except (OSError, ValueError, TypeError):
                    row["code"] = "sync_schedule_local_error"
                state["attempts"] += 1
                state["failures"] = min(20, state["failures"] + 1) if row["status"] == "FAIL" else 0
                multiplier = 2 ** max(0, state["failures"] - 1)
                delay = min(job["max_backoff_seconds"], job["interval_seconds"] * multiplier + padding)
                state["next_due"] = self._clock() + delay
                row.update(attempt=state["attempts"], consecutive_failures=state["failures"], next_attempt_in_seconds=delay,
                           finished_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
                rows.append(row)
                if emit is not None:
                    emit(row)
            return rows
        finally:
            self._lock.release()

    def next_delay(self) -> float | None:
        due = [self._state[job["job_id"]]["next_due"] for job in self._config["jobs"] if job["enabled"]]
        return max(0.0, min(due) - self._clock()) if due else None

    def run_once(self) -> dict:
        rows = self.run_due()
        return {"schema": REPORT_SCHEMA, "mode": "once", "status": "FAIL" if any(row["status"] == "FAIL" for row in rows) else "PASS",
                "config_sha256": self.config_sha256, "jobs": rows,
                "disabled_jobs": [job["job_id"] for job in self._config["jobs"] if not job["enabled"]]}

    def watch(self, emit, *, stop_event: Event, max_rounds: int | None = None) -> dict:
        if max_rounds is not None:
            _integer(max_rounds, 1, 1000000, "max_rounds")
        rounds, attempts = 0, 0
        while not stop_event.is_set():
            rows = self.run_due(stop_event=stop_event, emit=emit)
            attempts += len(rows)
            rounds += 1
            if max_rounds is not None and rounds >= max_rounds:
                break
            delay = self.next_delay()
            if delay is None:
                break
            stop_event.wait(delay)
        return {"schema": REPORT_SCHEMA, "mode": "watch", "status": "STOPPED", "config_sha256": self.config_sha256,
                "rounds": rounds, "attempts": attempts, "scheduling_state_persisted": False}
