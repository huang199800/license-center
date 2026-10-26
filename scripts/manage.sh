#!/usr/bin/env bash
set +x
set -euo pipefail
unset BASH_ENV ENV
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ $# -eq 0 ]]; then
  printf '%s\n' '用法: manage.sh {status|start|stop|restart|logs|version|doctor|update|backup|restore|uninstall} [选项]'
  exit 0
fi
exec python3 "$script_dir/deploy.py" "$@"
