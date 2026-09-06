#!/usr/bin/env python3
"""Check, run, or explicitly watch an operator-approved policy sync schedule."""
from __future__ import annotations

import argparse
import json
import signal
from threading import Event

from v17_policy_distribution import PolicyUpdateError
from v17_policy_sync import PolicySyncScheduler, check_sync_config, load_sync_config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "once", "watch"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True, help="Local operator-owned JSON schedule; relative paths use its directory")
        if name == "watch":
            command.add_argument("--max-rounds", type=int, help="Optional limit for a supervised finite run")
    args = parser.parse_args()
    try:
        config = load_sync_config(args.config)
        if args.command == "check":
            result = check_sync_config(config)
        else:
            scheduler = PolicySyncScheduler(config)
            if args.command == "once":
                result = scheduler.run_once()
            else:
                stop = Event()
                def request_stop(signum, frame):
                    stop.set()
                for name in ("SIGINT", "SIGTERM"):
                    if hasattr(signal, name):
                        signal.signal(getattr(signal, name), request_stop)
                result = scheduler.watch(lambda row: print(json.dumps(row, sort_keys=True), flush=True),
                                         stop_event=stop, max_rounds=args.max_rounds)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 1 if result["status"] == "FAIL" else 0
    except (PolicyUpdateError, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code if isinstance(exc, PolicyUpdateError) else "sync_schedule_config_unavailable",
                          "error": "schedule configuration or execution failed; inspect approved local inputs"}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
