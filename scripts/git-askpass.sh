#!/usr/bin/env sh
set +x
set -eu
case "${1:-}" in
  *[Uu]sername*) printf '%s\n' x-access-token ;;
  *[Pp]assword*) test -n "${LC_GIT_TOKEN_FILE:-}"; cat -- "$LC_GIT_TOKEN_FILE" ;;
  *) exit 1 ;;
esac
