#!/usr/bin/env python3
"""Bounded Linux Atheris campaign, using only the committed synthetic corpus."""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import v17_fuzz_targets as targets

SCHEMA = "ai-dfir/coverage-fuzz-run/v1.7"
ENGINE_VERSION = "3.1.0"
MAX_RUNS = 20000
MAX_LOG_BYTES = 8 * 1024 * 1024
WALL_SECONDS = 600
RSS_MIB = 512


def options(runs, seed):
    if type(runs) is not int or not 100 <= runs <= MAX_RUNS:
        raise ValueError("runs must be an integer from 100 through 20000")
    if type(seed) is not int or not 1 <= seed <= 4294967295:
        raise ValueError("seed must be a nonzero 32-bit unsigned integer")


def platform_check():
    if not __debug__:
        raise RuntimeError("fuzz assertions must be enabled")
    if sys.platform != "linux" or platform.machine() != "x86_64" or sys.version_info[:2] != (3, 12):
        raise RuntimeError("coverage campaign requires Linux x86_64 and CPython 3.12")
    if platform.python_implementation() != "CPython" or metadata.version("atheris") != ENGINE_VERSION:
        raise RuntimeError("install the pinned requirements-fuzz.txt profile")


def child_limits():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (WALL_SECONDS, WALL_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def private_write(path, raw):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def command(corpus, artifacts, runs, seed):
    options(runs, seed)
    return [sys.executable, str(ROOT / "scripts/fuzz_parsers_v17.py"), str(corpus),
            f"-runs={runs}", f"-seed={seed}", f"-max_len={targets.MAX_INPUT_BYTES}",
            "-timeout=5", f"-rss_limit_mb={RSS_MIB}", "-reload=0", "-print_final_stats=1",
            "-max_total_time=540", f"-artifact_prefix={artifacts}{os.sep}"]


def completion(log, runs):
    """Require actual native-engine completion and nonzero instrumented coverage."""
    lines = re.findall(rb"^#(\d+)\s+DONE\s+cov:\s*(\d+)\s+ft:\s*(\d+)", log, re.MULTILINE)
    stats = re.findall(rb"^stat::number_of_executed_units:\s*(\d+)\s*$", log, re.MULTILINE)
    if len(lines) != 1 or len(stats) != 1:
        raise RuntimeError("missing or ambiguous native fuzz completion")
    executed, coverage, features = map(int, lines[0])
    if executed < runs or int(stats[0]) != executed or coverage <= 0 or features <= 0:
        raise RuntimeError("incomplete native fuzz campaign")
    return {"executed_units": executed, "coverage_counters": coverage, "features": features}


def run(output, *, runs=5000, seed=17019):
    options(runs, seed)
    platform_check()
    preflight = targets.preflight()
    source_paths = tuple(name + ".py" for name in targets.INSTRUMENTED_MODULES) + (
        "scripts/fuzz_parsers_v17.py", "scripts/run_coverage_fuzz_v17.py", "requirements-fuzz.txt")
    source_hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in source_paths}
    output = Path(output).absolute()
    output.mkdir(mode=0o700)  # Exclusive: never overwrite a prior campaign.
    artifacts = output / "failures"
    artifacts.mkdir(mode=0o700)
    status, error_type, result, returncode = "FAIL", None, {}, None
    started = time.monotonic()
    try:
        # Native retained corpus is bounded by run count * maximum input length
        # (under 314 MiB at 20,000 runs), and removed on success or failure.
        with tempfile.TemporaryDirectory(prefix="corpus-", dir=output) as corpus_name:
            corpus = Path(corpus_name)
            for index, raw in enumerate(targets.seed_inputs()):
                private_write(corpus / f"seed-{index:02}", raw)
                private_write(corpus / f"empty-{index:02}", bytes([index]))
            log_path = output / "engine.log"
            with open(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
                process = subprocess.Popen(command(corpus, artifacts, runs, seed), cwd=ROOT,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True, preexec_fn=child_limits)
                try:
                    returncode = process.wait(timeout=WALL_SECONDS)
                except BaseException:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
                    raise
            with log_path.open("rb") as log:
                raw_log = log.read(MAX_LOG_BYTES + 1)
            if len(raw_log) > MAX_LOG_BYTES:
                raise RuntimeError("fuzz log exceeded bound")
            if returncode != 0 or any(artifacts.iterdir()):
                raise RuntimeError("fuzz engine failed or retained a failing input")
            result = completion(raw_log, runs)
            status = "PASS"
    except (Exception, KeyboardInterrupt) as exc:
        error_type = type(exc).__name__
    report = {"schema": SCHEMA, "status": status, "error_type": error_type,
              "engine": "Atheris", "engine_version": ENGINE_VERSION, "seed": seed,
              "python_version": platform.python_version(), "platform": "linux-x86_64",
              "source_sha256": source_hashes, "requested_runs": runs, "returncode": returncode,
              "elapsed_seconds": round(time.monotonic() - started, 3), **result,
              "profiles": list(targets.PROFILE_NAMES), "preflight": preflight,
              "max_input_bytes": targets.MAX_INPUT_BYTES, "wall_seconds": WALL_SECONDS,
              "rss_limit_mib": RSS_MIB, "log_limit_bytes": MAX_LOG_BYTES,
              "instrumented_modules": list(targets.INSTRUMENTED_MODULES),
              "coverage_guided": True, "native_sanitizers": False, "os_sandbox": False,
              "source_authenticity_verified": False, "collection_complete": None,
              "network_required": False, "exhaustive": False}
    private_write(output / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--runs", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=17019)
    args = parser.parse_args(argv)
    try:
        report = run(args.out_dir, runs=args.runs, seed=args.seed)
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps({key: report[key] for key in ("status", "requested_runs", "error_type")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
