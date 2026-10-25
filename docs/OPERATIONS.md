# 部署、运维、迁移与恢复

## 支持与验证范围

已实际执行：Windows x86_64、Python3.13.2、Node24.13.0、本机HTTP Uvicorn进程、SQLite并发事务及目录恢复。Python3.13仍在官方支持周期内，但本机补丁旧，**生产必须使用当前安全补丁**。容器及systemd文件以Linux x86_64/Python3.13为目标，目前环境没有Docker，未执行镜像构建、Linux或ARM验证。不要把提供配置等同于这些平台已验收。

生产入口必须HTTPS。逻辑issuer例如 `urn:company:licenses` 不含物理IP；对外使用 `licenses.example.com` 稳定域名。中心数据目录、客户端实例状态目录与应用发布目录分离。不要在客户源码中包含中心vault。

## 非容器方式

Windows按README启动命令，使用服务管理器以专用低权限服务账户运行，监听127.0.0.1，并用你已有的可信TLS反向代理对外提供服务。设置NTFS ACL：仅服务账户、备份操作员和必要的系统管理员访问data及业务缓存；Windows的chmod不能代替ACL。本版未自动更改用户ACL。

Linux部署示例（需在目标机验证）：

```sh
cd /opt/license-center
python3.13 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.2
.venv/bin/python -m pip install --require-hashes -r requirements.lock
umask 077
# /var/lib/license-center 由专用 license 用户拥有；以该账户初始化。
.venv/bin/python -m center.cli --data /var/lib/license-center init \
  --issuer urn:your-company:licenses --enrollment /secure/operator-enrollment.json
.venv/bin/python -m center.cli --data /var/lib/license-center seed --product demo
```

安装 `deploy/license-center.service` 后按系统标准启用服务；配置本机TLS网关转发到127.0.0.1:8000。不要启用对任意来源的 `X-Forwarded-For` 信任。提供的启动方式禁用proxy headers，应用直接用TCP来源限流，网关后的请求会按网关IP聚合；大规模上线前应在网关按实际客户端来源再限流并压测。管理员路径建议限制在VPN或运维网络。没有默认CORS跨站放行。

## Docker Compose 方式（未在本机执行）

1. 安装受支持Docker Engine与Compose，配置域名A/AAAA解析及80/443可达。
2. 复制 `.env.example` 为 `.env` 并设置真实 `LC_DOMAIN`；不要填写真实秘密到交付配置。
3. 创建 `operator-exchange`，将其所有者设置为容器UID10001、权限0700。此目录用于暂时交付MFA绑定材料、公钥和加密备份；不得放备份解密口令。

```sh
docker compose build
docker compose run --rm center init --issuer urn:your-company:licenses --enrollment /exchange/operator-enrollment.json
docker compose run --rm center seed --product demo
docker compose run --rm center public-keys --output /exchange/trusted-public-keys.json
# 导入TOTP，移走并安全删除exchange中的绑定材料。
docker compose up -d
docker compose ps
```

Caddy使用公有域名自动申请TLS证书。服务端口不直接发布到主机，中心使用非root用户、只读应用目录及独立持久卷。数据卷绝不能随应用更新删除。`python:3.13-slim` 和 `caddy:2` 是可变标签，上线流水线必须在目标平台完成构建测试后记录镜像digest，再用digest固定生产部署；本交付未虚构未验证的digest。

## 管理员与秘密

没有默认密码。初始化要求至少16字符密码和TOTP；密码scrypt哈希、TOTP种子加密保存在DB。初次绑定文件是秘密，导入验证器后保存在专门密码管理器并移除交换文件。TOTP允许前后一个30秒窗口，每个管理员每计数器只接受一次，登录与再次验证共享防重放状态。

```sh
python -m center.cli --data data add-admin --username operator1 --role operator --products demo --enrollment /secure/operator1-enrollment.json
python -m center.cli --data data add-admin --username auditor1 --role viewer --products demo --enrollment /secure/auditor1-enrollment.json
```

owner拥有全部产品；operator仅可修改被授予的产品；viewer只读。创建/分配管理员当前由服务器CLI执行，无网页管理员编辑器或密码重置界面。遗失验证器时由受控系统操作员创建替代账号，并在停服务维护窗口撤销原账号及会话；这一应急流程还需要双人审批的组织控制，当前无内置恢复码。

后台会话为一小时随机Bearer，仅存在页面内存，刷新页面需重新登录；不使用认证Cookie，不存在依赖Cookie的跨站自动认证。敏感接口需要Authorization头、JSON及一次性再次验证。CSP、输出textContent和禁止框架嵌入降低XSS风险；同源XSS仍可能窃取活跃Bearer，不能宣称完全消除。

`data/vault.json` 包含签名私钥、兑换码HMAC pepper、响应/TOTP数据加密密钥。磁盘访问控制由系统ACL/卷加密承担；vault不是客户端资产。数据库丢失vault后，不能恢复哈希码匹配、解密幂等结果与TOTP或继续原签名身份。提供备份已把数据库和vault放在加密包中；解密口令必须异地分权保管。

## 备份与校验

```sh
python -m center.cli --data data backup --output /backups/center-20261025.lcb
python -m center.cli verify-backup --input /backups/center-20261025.lcb
```

均交互输入独立、至少16字符备份口令；可由安全的任务运行器注入 `LC_BACKUP_PASSWORD`，不能将值写在命令行、日志或与备份同目录的配置中。此口令不是管理员密码。备份使用SQLite在线一致性快照、Scrypt派生独立密钥、AES-GCM认证加密，包含DB（产品、码摘要、权益、绑定、撤销、审计、幂等、管理员）和vault。签名私钥没有单独独立密钥保险库集成，运营上应另存受控离线应急副本。

应用独立配置（域名、环境、镜像digest、TLS网关配置、防火墙、证书账户、服务配置）必须另外进入加密配置备份/基础设施版本库。`vault`保存稳定issuer；备份不会自动收集整个操作系统环境，也不会恢复客户业务数据。

快照校验包含认证解密、格式版本、schema、数据库SHA-256、SQLite integrity/外键检查、issuer/key匹配和TOTP解密验证。备份过程中可继续处理普通授权API写入；密钥轮换/配置变更必须冻结。备份完成审计写在快照之后，因此该次backup.created事件在下一次快照才包含。

目标RPO：每15分钟成功备份时最多丢失约15分钟内的状态；目标RTO：小规模DB在30分钟内恢复服务。这是需演练验证的运维目标，不是本机测量SLA。未交付自动调度、异地复制、WAL/PITR持续归档或备份报警，因此没人配置定时备份时没有该RPO保证。建议保留小时/日/月多代并异地留存，定期在隔离机恢复。

## 计划迁移演练

1. 记录版本、镜像digest、issuer、可信kid和恢复口令持有方；新机装相同代码和依赖，验证磁盘ACL。提前降低稳定域名DNS TTL。
2. 暂停兑换、续费、激活等写流量，通过网关维护模式或停止旧服务实现停写；确认旧服务不会被编排器自动拉起。
3. 停写后做最终加密备份及 `verify-backup`，记录时点、SHA与交付链。应用配置另行备份。勿只复制运行中的center.db而忽略WAL。
4. 把包和代码交付新机，口令通过不同权限的独立渠道送达。

```sh
python -m center.cli restore --input /backups/final.lcb --destination /srv/license-center-restored --accept-stale-state
```

5. 目标目录必须原本不存在。恢复先在临时目录校验，写入一致数据，清空管理员旧会话并留下restore.completed审计，再发布新目录；不覆盖生产数据。配置 `LC_DATA` 指向新目录，继续使用同issuer和key。
6. 用原客户端凭据在隔离网络验证刷新、功能、期限、撤销、新兑换和续费（测试数据须与生产隔离）。检查原产品/码摘要/实例/审计数量和key一致。禁止新旧两边同时对生产开放写接口。
7. 切换DNS/TLS入口到新机，观察授权成功/刷新失败/延迟/租约/日志和数据量；保留旧机隔离只读。
8. 需要回退时，若新机**没有**接受生产写入，可直接隔离新机后回切旧机；若已有新写入，先停写新机，取其最终快照恢复到回退机，再切回。不能直接启用旧快照丢掉已发生的交易。

本项目 `python -m scripts.smoke` 自动覆盖其中本机TCP及隔离目录恢复步骤，不能代替跨服务器DNS/TLS/防火墙演练。

## 旧备份与对账

旧快照会回退已使用次数、续费、撤销、绑定、密钥和审计。恢复旧备份可能让已用码再次兑换或让已撤销权恢复。恢复工具要求显式 `--accept-stale-state`，它只表示操作者知情，不会自动补齐缺失数据。

```sh
python -m center.cli --data /salvaged/latest reconcile --other-data /recovered/old
```

该工具只读列出许可证、码、实例和兑换记录的缺失/变化ID，不输出完整兑换码，不自动重放交易。优先用幸存完整DB或更新的已验证快照替换旧快照；只有独立业务账本/订单及可信事件记录可供证实时，再由运维制定受审计数据修复方案。当前**没有自动增量补齐或通用事件重放器**；原库、增量和账本均丢失时，无法凭旧备份重建最新事实，需暂停售码/兑换、重建撤销清单并人工核对客户。

## 五类故障处置

|故障|动作与边界|
|---|---|
|计划迁移|按上述停写、最终快照、同身份恢复、切换、观察、带新写入回退流程|
|原服务器损坏|隔离旧地址/实例防止复活；用最新验证备份及独立口令恢复；按RPO对账并通报丢失时段|
|数据库损坏|停止写入，保全DB及WAL只读副本；先评估完整性与专业恢复；回到最近可验证备份，缺失段人工核对；不要对生产原件尝试破坏性修复|
|签名/vault遗失|从独立加密应急副本恢复；若永久丢失签名私钥，则无法继续原key签发；只剩公钥仍可验证旧token但不能延长，需通过可信软件更新分发新信任并安排重新发证；pepper/数据主密钥也遗失则需重置部分认证和兑换流程|
|签名密钥泄露|立即隔离签发环境、封堵泄露来源、记录时间与kid、生成新key，经可信发布渠道移除受损公钥并部署新信任，人工审查伪造证书范围；仅后台标撤销无法阻止泄露私钥伪造本地token；离线未更新客户无法即时获知|

## 密钥轮换

1. 先备份并停服务，确保没有旧worker继续签发；记录旧kid。
2. `python -m center.cli --data data rotate-key --service-stopped`。该参数是操作者声明，工具无法替代外部进程隔离。
3. `public-keys --output new-trust.json` 导出包含新旧两把公钥的配置，通过已经可信的程序更新/运维渠道分发。此时服务仍停止，因此不会抢先签发新key。
4. 客户端信任更新完成后再启服务；旧token用旧key验证，新token用新key。批量长期分发需设计过渡维护窗口，当前无自动key预发布服务。
5. 兼容期至少覆盖所有已签发凭证和离线文件最大寿命；旧私钥自动销毁、旧公钥撤下和密钥到期提醒尚未实现。正常退役可在停机维护时由受控人员审查后移除旧key；泄露时不能等兼容期，必须提前从客户端信任中撤销并接受旧token失效。

## 客户业务迁移

正常迁移：保全原业务数据及持久实例缓存，停止旧实例，再把状态目录搬到新部署；身份不依赖原IP，服务端许可剩余期限不改变。不要让原实例与复制实例同时运行。

设备损坏：保管许可证管理密钥；管理员再次验证后释放旧实例，等待其token_until（及自助流程冷却期）后，新机通过activate_existing/activateExisting用同许可证新增实例。不能靠无限重复解绑规避设备数。若管理密钥也遗失，须运营者通过已核验的线下客户关系审批，当前没有自动找回密钥接口。

扩容：在许可证允许的max_devices/max_online内申请独立实例，不能当作正常迁移免费复制无限节点。离线文件首次签发之外的转移/续签需后续实现，不能宣称后台释放可实时撤销离线旧文件。

## 数据库升级与监控

schema v1由 `center/migrations/001.sql` 在事务中首次创建；重复初始化迁移幂等。服务启动拒绝未知版本，不自动迁移生产库。未来升级必须先加密备份，在克隆库演练新迁移，验证业务与回滚条件后停写切换。当前没有v2迁移或一键降级；不可逆结构修改只能恢复快照并处理丢失写入，不能谎称脚本回滚无损。

已有：JSON结构化请求日志（路由、状态、延迟），不含请求体、完整码、Authorization或私钥；存活/就绪检查、owner指标接口、审计与备份恢复记录。应用日志可用于计算授权成功率和刷新失败率，但尚无Prometheus累计指标、Grafana面板、告警或自动恢复验证调度。

生产需接入日志采集，监控刷新失败比例与延迟分位数、429、当前租约、磁盘/DB/WAL大小、最近成功备份、恢复演练、可信key生命周期和TLS证书；配置日志脱敏、保留期限、远程审计归档及备份失败告警。故障诊断先区分网络、token到期、license到期、撤销、密钥不可信和配额，不能一律叫“授权失效”。
