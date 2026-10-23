#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ML_VENV="${SROS2_ML_VENV:-$HOME/.venvs/sros2-firewall}"
ROS_SETUP="${ROS_SETUP_FILE:-/opt/ros/jazzy/setup.bash}"

[[ -r "$ROS_SETUP" ]] || {
  printf 'missing ROS setup: %s\n' "$ROS_SETUP" >&2
  exit 1
}
[[ -x "$ML_VENV/bin/python" ]] || {
  printf 'missing ML test environment: %s\n' "$ML_VENV" >&2
  printf 'run: bash 工具腳本/setup_ml_test_env.sh\n' >&2
  exit 1
}

source "$ROS_SETUP"
set -u
export PYTHONPATH="$WORKSPACE${PYTHONPATH:+:$PYTHONPATH}"
cd "$WORKSPACE"
exec "$ML_VENV/bin/python" -m pytest "$@"
