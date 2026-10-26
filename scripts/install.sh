#!/usr/bin/env bash
set +x
set -euo pipefail
unset BASH_ENV ENV
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
command -v python3 >/dev/null || { printf '%s\n' '需要python3；请使用bootstrap.sh完成首次环境准备。' >&2; exit 1; }
exec python3 "$script_dir/deploy.py" install "$@"
