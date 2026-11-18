#!/usr/bin/env bash
# Local bundle setup. Does not create a remote, push, or deploy.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d tools ]; then
  echo "tools/ is missing. Download it with: python3 obf/fetch_tools.py" >&2
  exit 1
fi

# ZIP tools may drop the relative symlink used by the frozen baseline tests.
if [ -L tests/baseline/tools ] && [ ! -e tests/baseline/tools ]; then
  rm -f tests/baseline/tools
fi
if [ ! -e tests/baseline/tools ]; then
  ln -s ../../tools tests/baseline/tools
  echo "restored tests/baseline/tools -> ../../tools"
fi

if [ "${1:-}" = "--self-test" ]; then
  echo "Running full CLI self-test; this can take about 15 minutes."
  PYTHONPATH=. python3 -m obf.cli --self-test
else
  echo "Local setup ready."
  echo "Start the app: PORT=8000 OBF_MAX_SOURCE=10485760 OBF_TIMEOUT=300 python3 -m obf.web"
  echo "Optional full verification: ./setup-local.sh --self-test"
fi
