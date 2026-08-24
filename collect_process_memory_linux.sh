#!/usr/bin/env bash
set -euo pipefail
PID=""
OUT=""
MIN_FREE_GB="8"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) PID="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --min-free-gb) MIN_FREE_GB="$2"; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

if [[ -z "$PID" || -z "$OUT" ]]; then
  echo "Usage: sudo bash collect_process_memory_linux.sh --pid PID --out DIR [--min-free-gb 8]" >&2
  exit 2
fi
if ! command -v gcore >/dev/null 2>&1; then
  echo "gcore is not installed; refusing memory acquisition." >&2
  exit 1
fi

mkdir -p "$OUT"
FREE_KB=$(df -Pk "$OUT" | awk 'NR==2 {print $4}')
MIN_KB=$((MIN_FREE_GB*1024*1024))
if [[ "$FREE_KB" -lt "$MIN_KB" ]]; then
  echo "Insufficient free space: ${FREE_KB}KB < required ${MIN_KB}KB" >&2
  exit 1
fi

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/acquisition_start_utc.txt"
gcore -o "$OUT/core" "$PID" > "$OUT/gcore.stdout.txt" 2> "$OUT/gcore.stderr.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/acquisition_end_utc.txt"
chmod 600 "$OUT"/core.* || true
(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt"
echo "Process memory acquired. Treat the dump as highly sensitive evidence."
