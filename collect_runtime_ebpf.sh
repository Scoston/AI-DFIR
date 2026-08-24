#!/usr/bin/env bash
set -euo pipefail
PID=""
OUT=""
DURATION="60"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) PID="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    *) echo "Unknown argument: $1"; exit 2;;
  esac
done

if [[ -z "$PID" || -z "$OUT" ]]; then
  echo "Usage: sudo bash collect_runtime_ebpf.sh --pid <PID> --out <dir> [--duration 60]"
  exit 2
fi
if ! command -v bpftrace >/dev/null 2>&1; then
  echo "bpftrace is required for this optional collector." >&2
  exit 1
fi

mkdir -p "$OUT"
SCRIPT="$OUT/ai_dfir_trace.bt"
cat > "$SCRIPT" <<'BPF'
tracepoint:syscalls:sys_enter_openat /pid == TARGET/ {
  printf("{\"kind\":\"openat\",\"ts_ns\":%llu,\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\"}\n",
         nsecs, pid, comm, str(args->filename));
}
tracepoint:syscalls:sys_enter_execve /pid == TARGET/ {
  printf("{\"kind\":\"execve\",\"ts_ns\":%llu,\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\"}\n",
         nsecs, pid, comm, str(args->filename));
}
tracepoint:syscalls:sys_enter_connect /pid == TARGET/ {
  printf("{\"kind\":\"connect\",\"ts_ns\":%llu,\"pid\":%d,\"comm\":\"%s\",\"fd\":%d,\"addrlen\":%d}\n",
         nsecs, pid, comm, args->fd, args->addrlen);
}
BPF

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/start_utc.txt"
set +e
timeout "$DURATION" bpftrace -D TARGET="$PID" "$SCRIPT" > "$OUT/events.jsonl" 2> "$OUT/bpftrace.stderr"
RC=$?
set -e
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/end_utc.txt"

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt"

# timeout normally exits 124; treat that as expected collection completion.
if [[ "$RC" -ne 0 && "$RC" -ne 124 ]]; then exit "$RC"; fi
echo "eBPF evidence: $OUT"
