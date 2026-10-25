#!/usr/bin/env bash
# Public bootstrap: no application code or credentials. Review and hash-pin before use.
set +x
set -euo pipefail
umask 077
unset GIT_TRACE GIT_TRACE_PACKET GIT_CURL_VERBOSE BASH_ENV ENV
repo=huang199800/license-center
ref=''
commit=''
root=/opt/license-center
config=''
non_interactive=0
ssh_mode=0
token_file=''
action=install
bundle=''
stale=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --ref) ref="$2"; shift 2 ;;
    --commit) commit="$2"; shift 2 ;;
    --root) root="$2"; shift 2 ;;
    --config) config="$2"; shift 2 ;;
    --git-token-file) token_file="$2"; shift 2 ;;
    --ssh) ssh_mode=1; shift ;;
    --non-interactive) non_interactive=1; shift ;;
    --restore) action=restore; shift ;;
    --bundle) bundle="$2"; shift 2 ;;
    --accept-stale-state) stale=1; shift ;;
    --help) echo 'bootstrap.sh --ref vX.Y.Z|COMMIT --commit FULL_SHA [--config PROTECTED_JSON --non-interactive] [--root PATH] [--repo OWNER/REPO] [--ssh|--git-token-file FILE] [--restore --bundle FILE --accept-stale-state]'; exit 0 ;;
    *) echo '未知引导参数。' >&2; exit 1 ;;
  esac
done
[[ "$repo" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ && "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo '需要OWNER/REPO和完整40位提交SHA。' >&2; exit 1; }
[[ "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ || "$ref" == "$commit" ]] || { echo '只允许固定发布标签或相同提交SHA。' >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo '请以root或sudo执行安装。' >&2; exit 1; }
[[ "$root" == /* && "$root" != / && "$root" != /opt && "$root" != /etc && "$root" != /var && "$root" != *..* ]] || { echo '安装根目录不安全。' >&2; exit 1; }
if ! command -v python3 >/dev/null || ! command -v git >/dev/null; then
  command -v apt-get >/dev/null || { echo '需要Debian/Ubuntu、python3和git。' >&2; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 git ca-certificates
fi
if [[ -n "$token_file" ]]; then
  python3 - "$token_file" <<'PY'
import os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]).resolve(strict=True)
if not p.is_file() or p.stat().st_mode&0o077 or p.stat().st_uid!=os.geteuid():raise SystemExit('Token文件必须由当前用户拥有且权限0600')
PY
fi
destination="$root/releases/$commit"
if [[ ! -d "$destination/.git" ]]; then
  [[ ! -e "$destination" ]] || { echo '下载目录已存在但不是受控Git检出；停止。' >&2; exit 1; }
  mkdir -p -- "$destination"
  remote="https://github.com/$repo.git"
  [[ "$ssh_mode" == 0 ]] || remote="git@github.com:$repo.git"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "$remote"
  if [[ -n "$token_file" ]]; then
    helper="$(mktemp /tmp/lc-askpass.XXXXXXXX)"
    trap 'rm -f -- "$helper"' EXIT
    printf '%s\n' '#!/bin/sh' 'set +x' 'case "$1" in *[Uu]sername*) printf "%s\n" x-access-token;; *[Pp]assword*) cat -- "$LC_GIT_TOKEN_FILE";; *) exit 1;; esac' > "$helper"
    chmod 0700 "$helper"
    export GIT_ASKPASS="$helper" LC_GIT_TOKEN_FILE="$token_file" GIT_TERMINAL_PROMPT=0
    # Stderr can contain untrusted remote text. Credentials never enter URL/argv.
    if ! git -C "$destination" fetch --quiet --depth 1 origin "$ref" 2>/dev/null; then echo '仓库认证或下载失败。' >&2; exit 1; fi
    rm -f -- "$helper"
    trap - EXIT
    unset GIT_ASKPASS LC_GIT_TOKEN_FILE
  else
    if ! GIT_TERMINAL_PROMPT=0 git -C "$destination" fetch --quiet --depth 1 origin "$ref" 2>/dev/null; then echo '仓库下载失败；私有仓库需预配置只读SSH密钥或--git-token-file。' >&2; exit 1; fi
  fi
  actual="$(git -C "$destination" rev-parse FETCH_HEAD)"
  [[ "$actual" == "$commit" ]] || { echo '标签解析结果与固定提交不一致，停止。' >&2; exit 1; }
  git -C "$destination" checkout --quiet --detach "$commit"
fi
[[ "$(git -C "$destination" rev-parse HEAD)" == "$commit" ]] || { echo '已有源码提交不一致。' >&2; exit 1; }
args=(--root "$root")
[[ -z "$config" ]] || args+=(--config "$config")
[[ "$non_interactive" == 0 ]] || args+=(--non-interactive)
if [[ "$action" == restore ]]; then
  [[ -n "$bundle" && "$stale" == 1 ]] || { echo '恢复需要--bundle和--accept-stale-state。' >&2; exit 1; }
  args+=(--bundle "$bundle" --accept-stale-state)
fi
exec bash "$destination/scripts/$action.sh" "${args[@]}"
