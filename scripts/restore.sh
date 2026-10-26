#!/usr/bin/env bash
set +x
set -euo pipefail
unset BASH_ENV ENV
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 "$script_dir/deploy.py" restore "$@"
