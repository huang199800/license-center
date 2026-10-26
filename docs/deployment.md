# 原生安装与运维（v1.2.0）

默认使用系统 Python 3.10+、独立虚拟环境、专用非登录账户及 systemd。不会安装 Docker、Caddy 或 Nginx，不监听80/443，不改防火墙。默认只监听 `127.0.0.1:43871`；SQLite不开放网络端口。已有网关负责域名HTTPS。Docker作为显式可选后端保留，见 [历史容器部署](deployment-docker.md)。

允许 Debian12/13、Ubuntu22.04/24.04/26.04，x86_64/aarch64，要求root/sudo、systemd系统实例、至少3GiB空闲，能访问GitHub、系统APT源和PyPI。CI设置Ubuntu22.04/24.04 x86_64原生安装实测；具体成功提交和结果见发布说明。Debian、ARM及两台物理服务器迁移需另验。

## 首次安装

从发布说明取得固定40位提交及bootstrap SHA-256，下载、审阅并校验 `scripts/bootstrap.sh`，再通过该脚本固定提交下载源码。发布说明提供已填妥命令，不执行浮动main。公开仓库无需Token；私有下载仍支持只读SSH或0600 Token文件，认证材料不进入URL或Git remote。

已有固定提交的干净源码时：

```sh
sudo bash scripts/install.sh --mode native
```

首次询问外部域名、本机端口和稳定issuer。域名描述现有网关，填写域名也不会申请80/443。端口占用时明确报出 `REQUESTED_PORT_IN_USE_127.0.0.1_43871`，可选择其他本机高位端口。安装器准备系统python3-venv、按锁文件哈希安装二进制依赖、创建数据库及管理员、启用systemd并检查服务。

无人值守JSON放到仓库外 `/root/license-install.json`，权限0600：

```json
{
  "repo": "huang199800/license-center",
  "domain": "sq.hhse.top",
  "port": 43871,
  "issuer": "urn:license-center:production"
}
```

```sh
sudo bash scripts/install.sh --mode native --config /root/license-install.json --non-interactive
```

首次生成独立随机管理员密码、业务备份口令和密钥备份口令，保存在 `/etc/license-center-secrets/<部署ID>/`，目录0700、文件0600，不打印内容。可注入 `admin_password_file`、`backup_password_file`、`key_password_file` 的绝对路径，文件至少16字符，两个备份口令不得相同。MFA材料位于 `/opt/license-center/exchange/admin-enrollment.json`。安全读取密码与MFA材料导入验证器，再分权转移到密码管理器，不粘贴进日志或发给他人。

摘要显示域名、实际本机监听地址、服务名、版本和数据目录。域名HTTPS可能显示待配置；本机API健康不代表公网HTTPS已完成。重复安装同一提交只启动和检查已有服务，不重建管理员或签名身份；不同提交使用升级入口。上次仅在端口检查退出、没有deployment.json及state的安装可直接改用原生入口。已有Docker业务不能原地切模式，应恢复到新目录。

## 现有 Caddy 接入

仅当Caddy在宿主机或共享宿主机网络运行时，把下列站点合并到实际生效配置。已有同名站点应编辑原配置，不重复添加或覆盖其他站点：

```caddyfile
sq.hhse.top {
    request_body {
        max_size 64KB
    }
    reverse_proxy 127.0.0.1:43871
}
```

先备份并校验配置，再通过现有管理方式热重载。普通Docker bridge中的Caddy不能通过其自身127.0.0.1连接宿主机，应另行设计私网连接。不要公开绑定授权服务。域名A/AAAA指向正确服务器，现有网关负责证书。最后检查 `https://sq.hhse.top/health/ready` 和后台。安装器不修改网关。参考 [Caddy官方文档](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)。

## 统一管理

以下从固定源码目录执行，统一支持 `--root`，摘要会显示绝对入口路径：

```sh
sudo bash scripts/manage.sh status
sudo bash scripts/manage.sh start
sudo bash scripts/manage.sh stop
sudo bash scripts/manage.sh restart
sudo bash scripts/manage.sh version
sudo bash scripts/manage.sh logs
sudo bash scripts/doctor.sh
sudo bash scripts/backup.sh
sudo bash scripts/update.sh --ref REPLACE_RELEASE_TAG --commit REPLACE_FULL_40_CHARACTER_COMMIT
```

升级命令的大写值是**必须替换**的占位符。日志只输出白名单请求事件，不原样转储journal。专用服务 `license-center-<部署ID>.service` 随系统启动。`manage.sh uninstall` 停用服务，保留业务、密钥、程序、配置、备份和专用账户，没有默认彻底清理。

## 持久化、升级与恢复

程序在 `releases/<commit>` 和 `runtimes/<commit>/{app,venv}`，root拥有，服务账户只读；数据库及许可证在 `state/data`，签名身份在 `state/keys`，配置在 `config`，绑定材料与备份交换文件在 `exchange`，备份在 `backups`。日志由journal管理。服务仅对state有写权限，参见 [systemd权限说明](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec)。

升级固定源码提交，先准备新虚拟环境，再停止服务、执行一致性加密备份，切换unit并检查API、后台、数据库及隔离授权功能。schema不兼容时拒绝自动升级。保留旧程序、数据和签名身份。失败输出备份与旧runtime位置及恢复入口，不承诺自动数据库回退。新服务已产生写入时，先保全当前数据，再决定是否恢复；旧备份之后的记录需要补录或对账。

备份恢复见 [迁移文档](migration.md)。元数据未标backend的旧部署按Docker处理，拒绝显式跨模式原地操作。
