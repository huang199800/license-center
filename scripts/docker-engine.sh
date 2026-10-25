#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || { echo '需要root安装Docker依赖。' >&2; exit 1; }
# /etc/os-release is owned by the operating system, never by a supplied config.
. /etc/os-release
case "$ID:$VERSION_ID" in
  ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) echo '未支持的Debian/Ubuntu版本。' >&2; exit 1 ;;
esac
if command -v docker >/dev/null; then
  docker info >/dev/null
  docker compose version >/dev/null
  exit 0
fi
# Refuse conflicting installations; never remove another project's container runtime.
for package in docker.io docker-compose podman-docker containerd runc; do
  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
    echo '发现已有容器运行时，请管理员按Docker官方文档处理兼容性；不会自动卸载。' >&2
    exit 1
  fi
done
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -d -m 0755 /etc/apt/keyrings
key=/etc/apt/keyrings/license-center-docker.asc
sources=/etc/apt/sources.list.d/license-center-docker.sources
[[ ! -e "$key" && ! -e "$sources" ]] || { echo 'Docker专用APT文件已存在，请先诊断；不会覆盖。' >&2; exit 1; }
curl --proto '=https' --tlsv1.2 --fail --silent --show-error "https://download.docker.com/linux/$ID/gpg" -o "$key"
fingerprint="$(gpg --batch --show-keys --with-colons "$key" 2>/dev/null | awk -F: '$1=="fpr" {print $10;exit}')"
[[ "$fingerprint" == 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]] || { echo 'Docker签名密钥指纹不匹配。' >&2; exit 1; }
chmod a+r "$key"
arch="$(dpkg --print-architecture)"
codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
printf 'Types: deb\nURIs: https://download.docker.com/linux/%s\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: %s\n' "$ID" "$codename" "$arch" "$key" > "$sources"
chmod 0644 "$sources"
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker info >/dev/null
docker compose version >/dev/null
echo 'Docker Engine与Compose插件已就绪；未修改防火墙。'
