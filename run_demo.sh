#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
elif [[ -f ".venv/Scripts/activate" ]]; then
  # Git Bash on Windows
  # shellcheck disable=SC1091
  source ".venv/Scripts/activate"
fi

PYTHON="${PYTHON:-python3}"
if [[ -x ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
  PYTHON=".venv/Scripts/python.exe"
fi

"$PYTHON" -c 'import sys; sys.version_info >= (3, 12) or sys.exit("Python 3.12+ is required")'
"$PYTHON" -m pip --version >/dev/null
"$PYTHON" run_demo.py