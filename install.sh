#!/usr/bin/env bash
set -euo pipefail
PROFILE="${1:-default}"
PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"

"$PYTHON" -c 'import sys; assert sys.version_info >= (3,11), "AI-DFIR requires Python 3.11+"'
"$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip
case "$PROFILE" in
  minimal|default) pip install -r requirements.txt ;;
  model) pip install -r requirements-model.txt ;;
  enterprise) pip install -r requirements-enterprise.txt ;;
  dev) pip install -r requirements-dev.txt ;;
  pdf-agpl)
    pip install -r requirements.txt
    pip install -r requirements-pdf-agpl.txt
    echo 'WARNING: PyMuPDF is AGPL/commercial. Review LICENSE_GUIDE.md.' >&2
    ;;
  *) echo "Unknown profile: $PROFILE" >&2; exit 2 ;;
esac
python -m py_compile ./*.py
printf '\nAI-DFIR installed in %s using profile %s\n' "$VENV" "$PROFILE"
printf 'Activate with: source %s/bin/activate\n' "$VENV"
