# 第十三章：公开仓库、安装与运维

按用户后续授权，本次交付改为**公开仓库和完整源码公开下载**，不再要求默认私有。仓库为 [huang199800/license-center](https://github.com/huang199800/license-center)。私有部署的两种认证路线仍保留，供以后切回私有时使用。

## 当前验收状态

版本：1.1.0，数据库schema1。**尚未完成干净Debian/Ubuntu服务器上的Docker安装验收**：本机Windows没有可运行Docker/WSL，用户暂无测试服务器。不能把脚本存在、单元测试或CI工作流文件存在当作已部署。仓库Actions中的真实Docker任务成功后，才能把对应Ubuntu版本标为已验证；Debian与ARM需各自另验。

目标系统白名单：Debian12/13、Ubuntu22.04/24.04/26.04，x86_64/aarch64。白名单表示安装器允许尝试，**不是已经逐一实测**。建议先在Ubuntu24.04 x86_64测试机验收，生产保留快照。要求root/sudo、至少3GiB空闲、本机rootful Docker Engine28+及Compose插件、可访问GitHub/PyPI/Docker官方镜像和APT源。远程Docker上下文及rootless UID映射暂不支持，会明确拒绝。不会关闭防火墙或卸载已有容器运行时。

## 没有源码的新服务器

公开引导脚本是 `scripts/bootstrap.sh`，它只做环境引导、固定提交下载和调用安装器，不包含业务数据或秘密。发布后应从固定提交URL下载，先审阅脚本，再按**独立可信渠道取得**的SHA-256校验；最后调用时固定完整40位提交。不要直接执行不断变化的main分支。

以下是**需要替换的大写占位符模板，不是已经填妥的一键命令**；本次交付消息/发行说明会给实际发布提交与脚本hash。校验值与脚本若只来自同一个已被攻陷的渠道，不能建立独立信任。

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/huang199800/license-center/REPLACE_FULL_COMMIT/scripts/bootstrap.sh -o /tmp/lc-bootstrap.sh && printf '%s  %s\n' REPLACE_BOOTSTRAP_SHA256 /tmp/lc-bootstrap.sh | sha256sum -c - && sudo bash /tmp/lc-bootstrap.sh --ref REPLACE_FULL_COMMIT --commit REPLACE_FULL_COMMIT
```

前置认证对公开源码不需要Token。首次交互询问域名、稳定issuer以及是否安装Docker。依赖缺失时准备Python3/Git，Docker安装需明确选择；通过[Docker官方Debian/Ubuntu签名APT仓库](https://docs.docker.com/engine/install/ubuntu/)安装Engine和Compose插件，校验官方密钥指纹，拒绝自动移除冲突运行时。

已有经校验的源码也可一条入口启动：`sudo bash scripts/install.sh`。源码必须处于干净Git提交；源码包未带Git历史时，先按公开仓库固定提交检出，不允许凭一个版本字符串冒充已校验提交。

## 无人值守模式

把 `deploy/install-config.example.json` 复制到仓库外受保护文件，例如 `/root/license-install.json`，权限0600。JSON只当数据读取，不通过shell source执行；不支持把Token/管理员密码直接写成配置值，秘密只提供文件路径。

```json
{
  "repo": "huang199800/license-center",
  "domain": "licenses.example.com",
  "issuer": "urn:my-company:licenses",
  "admin_username": "admin",
  "port": 18080,
  "auto_install_docker": true,
  "ssh": false
}
```

```sh
sudo bash scripts/install.sh --root /opt/license-center --config /root/license-install.json --non-interactive
```

未指定秘密路径时，首次生成三个独立随机文件：管理员密码、业务备份口令、密钥备份口令，默认目录 `/etc/license-center-secrets/<部署ID>/`（0700，文件0600）。文件内容不会打印；最终摘要只显示路径。无人值守也可以预先提供 `admin_password_file`、`backup_password_file`、`key_password_file` 的绝对路径；文件必须当前操作员/root拥有且权限0600，备份两个口令必须不同。`secret_dir` 必须位于源码及部署根目录之外。

首次MFA绑定材料在 `/opt/license-center/exchange/admin-enrollment.json`，不能公开下载或打印进日志。运维人员安全读取后导入验证器，并把恢复材料分权转移到密码管理器后安全移走本地副本。登录同时需要随机密码和TOTP。重复安装同一提交不会执行init，不重置密码、不生成新签名密钥；不同提交要求显式update。

## 文件、端口和持久化

|位置|用途|
|---|---|
|`ROOT/releases/<commit>/`|只读发布源码，不能放秘密|
|`ROOT/state/data/`|SQLite、许可证/兑换/实例/撤销/审计/幂等事实|
|`ROOT/state/keys/vault.json`|签名身份、码摘要pepper和数据加密主密钥|
|`ROOT/config/config.json`|受保护独立配置；只保存秘密路径|
|`ROOT/deployment.json`、`config/version.json`|版本、提交、schema、应用镜像ID、基础镜像digest|
|`ROOT/compose.generated.json`|安装器生成的实际Compose配置|
|`ROOT/backups/`|双口令加密备份包及校验和|
|`ROOT/exchange/`|受控临时交付目录，非Web静态目录|
|Docker json-file日志|轮转10MiB×5，管理入口只输出白名单字段|

应用容器为UID10001，数据和key目录分别持久化，不随源码或容器重建删除。维护辅助容器只在读取受保护材料时以root启动，随后降权10001再操作SQLite，防止产生root拥有的WAL；正常API容器没有额外capabilities。

`port` 默认18080，始终只绑定127.0.0.1。无域名时不启动公网网关，可从自己电脑执行 `ssh -L 18080:127.0.0.1:18080 USER@SERVER`，再打开本机 `http://127.0.0.1:18080/`。这里的USER/SERVER是明显占位符。

配置域名时Caddy监听80/443并申请证书；域名需正确解析、端口需安全组/防火墙允许。证书或DNS未就绪时摘要显示 `pending_dns_or_certificate_see_docs`，此时应通过SSH隧道处理，不能把HTTP本机端口改绑0.0.0.0冒充HTTPS。后台API始终需要密码+MFA会话，SQLite没有对公网数据库端口。

## 统一管理

使用已安装版本的 `ROOT/releases/<commit>/scripts/manage.sh`：

```sh
sudo bash scripts/manage.sh status --root /opt/license-center
sudo bash scripts/manage.sh start --root /opt/license-center
sudo bash scripts/manage.sh stop --root /opt/license-center
sudo bash scripts/manage.sh restart --root /opt/license-center
sudo bash scripts/manage.sh logs --root /opt/license-center
sudo bash scripts/manage.sh version --root /opt/license-center
sudo bash scripts/doctor.sh --root /opt/license-center
sudo bash scripts/backup.sh --root /opt/license-center
sudo bash scripts/manage.sh uninstall --root /opt/license-center
```

`doctor`检查系统/Docker/Compose、数据库就绪、管理页、可信公钥，以及临时隔离数据库的真实兑换→签名校验→续费→刷新。它不会向生产库创建测试授权。logs仅输出应用已知JSON请求事件的method/route/status/ms，不转发不认识的日志行或外部命令错误正文。

卸载只执行本项目Compose down，不删除数据、key、配置、备份或网关卷。没有隐含彻底清理选项；彻底清理需在独立维护操作中先列出路径、验证备份并由管理员执行，不能和卸载混为一谈。

## 指定版本升级

```sh
# 下面两个大写值必须替换为真实发布标签和对应40位SHA。
sudo bash scripts/update.sh --root /opt/license-center --ref REPLACE_RELEASE_TAG --commit REPLACE_FULL_COMMIT
```

也可把ref设置为与commit相同的40位SHA。main/master等开发分支被拒绝。下载先核对Git实际提交；检查当前schema在目标release.json允许范围；先构建镜像，再停服务完成最终备份，再切新版本、健康检查及隔离授权功能验证。当前仅支持schema1兼容应用更新，任何数据库结构版本变化都拒绝自动升级，需单独审查迁移。

配置、data和key保留。安装时解析并记录Python/Caddy镜像digest；依赖带哈希锁。从本地源码构建，不需要私有镜像仓库；如运营者将基础镜像改为私有镜像，应先用Docker官方凭据存储/`docker login --password-stdin`配置，不把密码作为build-arg或放进Dockerfile。密码管理器/系统凭据存储由运营者负责。

失败会输出备份位置、原版本/提交及恢复建议，不自动把旧DB覆盖到可能已经接收新业务的DB。应用回退在相同schema时可显式update到旧提交；数据库回退是恢复历史事实，可能丢失续费/兑换/撤销，必须按迁移文档停写、对账再执行。

## 可选私有仓库路线

A. **只读SSH部署密钥**：按[GitHub部署密钥说明](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys)，将新服务器的公钥加到指定私库Deploy keys，关闭写权限；私钥只在服务器/root的SSH配置或ssh-agent里。提前通过独立渠道核对github.com主机指纹，保持StrictHostKeyChecking，不用未经核对的ssh-keyscan结果自动信任。首次 `git clone --branch <固定标签> git@github.com:OWNER/REPO.git` 完成认证后执行install；配置repo和ssh=true用于后续更新。

B. **公开通用bootstrap + 私库源码**：将本交付 `scripts/bootstrap.sh` 作为唯一文件发布在另一个公开引导仓库；审阅、版本固定并校验其hash后，传 `--repo OWNER/REPO --ssh`，或 `--git-token-file /root/protected-token`。Token选择仅指定仓库Contents:read的细粒度Token，设置有效期；不要默认使用全账号权限。凭据只通过GIT_ASKPASS读取受保护文件，remote URL始终不带凭据。后续升级在独立配置中设置相同 `git_token_file` 绝对路径或重新配置SSH，不复制token进源码、镜像或备份包。

私有认证链路当前未实测；公开下载是用户选定并将验证的默认链路。不要把GitHub账号绑定误认为新服务器自动获得私有仓库访问权。
