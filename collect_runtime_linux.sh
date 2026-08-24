#!/usr/bin/env bash
set -euo pipefail

PID=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) PID="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 2 ;;
  esac
done

if [[ -z "$PID" || -z "$OUT" ]]; then
  echo "Usage: sudo bash collect_runtime_linux.sh --pid <PID> --out <evidence_dir>"
  exit 2
fi

mkdir -p "$OUT"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/acquisition_time_utc.txt"
hostname > "$OUT/hostname.txt" || true
uname -a > "$OUT/uname.txt" || true
ps auxww > "$OUT/processes.txt" || true
nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1 || true
nvidia-smi -q > "$OUT/nvidia-smi-q.txt" 2>&1 || true
docker ps --no-trunc > "$OUT/docker-ps.txt" 2>&1 || true

if [[ -r "/proc/$PID/cmdline" ]]; then
  tr '\0' ' ' < "/proc/$PID/cmdline" > "$OUT/model_cmdline.txt"
fi

# RESTRICTED: can contain API keys, tokens, and other secrets.
if [[ -r "/proc/$PID/environ" ]]; then
  tr '\0' '\n' < "/proc/$PID/environ" > "$OUT/model_environment_RESTRICTED.txt"
  chmod 600 "$OUT/model_environment_RESTRICTED.txt" || true
fi

if command -v lsof >/dev/null 2>&1; then
  lsof -p "$PID" > "$OUT/model_open_files.txt" 2>&1 || true
fi

if [[ -r "/proc/$PID/maps" ]]; then
  cat "/proc/$PID/maps" > "$OUT/model_memory_maps.txt"
fi

if [[ -d "/proc/$PID/fd" ]]; then
  ls -la "/proc/$PID/fd" > "$OUT/model_fd_listing.txt" 2>&1 || true
fi

python3 -m pip freeze > "$OUT/python_packages.txt" 2>&1 || true

# Focused, non-destructive source/config hunt in common deployment paths.
for d in /app /opt /workspace /srv; do
  if [[ -d "$d" ]]; then
    grep -RniE \
      'register_forward_hook|register_forward_pre_hook|control.?vector|steering|hidden_states|residual|abliterat|uncensored|PeftModel|load_adapter|set_adapter|merge_and_unload' \
      "$d" > "$OUT/keyword_hits$(echo "$d" | tr '/' '_').txt" 2>/dev/null || true
  fi
done

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt"

echo "Runtime evidence collected to $OUT"
echo "Review model_environment_RESTRICTED.txt as sensitive evidence."
