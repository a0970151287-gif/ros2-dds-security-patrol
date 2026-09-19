#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ML_VENV="${SROS2_ML_VENV:-$HOME/.venvs/sros2-firewall}"
REQUIREMENTS="$WORKSPACE/ML防禦/requirements.txt"

[[ -f "$REQUIREMENTS" ]] || {
  printf 'missing requirements: %s\n' "$REQUIREMENTS" >&2
  exit 1
}

if [[ ! -x "$ML_VENV/bin/python" ]]; then
  python3 -m venv --system-site-packages "$ML_VENV"
fi

"$ML_VENV/bin/python" -m pip install --requirement "$REQUIREMENTS"
printf 'ml_test_environment=%s\n' "$ML_VENV"
printf 'next: bash 工具腳本/run_full_tests.sh\n'
