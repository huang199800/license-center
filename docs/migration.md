# 一键备份、恢复与迁移

部署脚本使用新 `.lcb2` 格式；原先 `python -m center.cli backup` 的单口令 `.lcb` 仍可用于开发，但二者不能混称为同一种备份。完整故障处置和RPO/RTO规则同时参考 [OPERATIONS.md](OPERATIONS.md)。

## 双口令备份

```sh
sudo bash scripts/backup.sh --root /opt/license-center
# 或显式指定一个尚不存在的文件：
sudo bash scripts/backup.sh --root /opt/license-center --output /secure-backups/center.lcb2
```

包含SQLite一致性快照（产品/套餐/许可证/码摘要/兑换/续费/实例/换绑/撤销/审计/幂等/管理员）、独立配置、软件版本、commit、schema、快照清单及vault恢复材料。数据库及配置由备份口令加密；vault由另一个独立口令加密，两者不得相同。密钥本体不会明文出现在包里，GitHub访问凭据文件不会被收集，只有配置中的路径。口令文件在源码与备份目录之外，必须另经不同权限的保险库/离线渠道备份，不能只保留磁盘上的唯一一份。

使用Scrypt+A​ES-GCM，格式及版本元数据纳入认证上下文；篡改header、错误任一口令或损坏内容均拒绝恢复。另写SHA-256检查和用于传输核对；仅有未认证校验和不足以证明备份真实性。普通备份使用SQLite在线快照，计划迁移必须先stop旧服务再做最终备份，避免快照之后继续产生业务状态。

## 新机恢复入口

1. 新机准备与包中**完全相同提交**的代码，或使用已校验bootstrap传 `--restore` 下载该提交。不要相信未解密包中header作为任意代码执行来源；来源应为你已核验的发布仓库，header只是选择版本参考，解密时还会验证其认证。
2. 准备受保护恢复配置（0600）：

```json
{
  "domain": "licenses.example.com",
  "port": 18080,
  "auto_install_docker": true,
  "backup_password_file": "/root/restore-material/state-password",
  "key_password_file": "/root/restore-material/key-password"
}
```

3. 文件和值均为示例；两个文件内容分别从独立保险库取得，不要把解密材料放到备份目录。目标部署根目录不能已有state或deployment记录。恢复显示目标、覆盖范围和备份时间；交互输入RESTORE，或无人值守时同时显式提供接受旧时点参数。

```sh
sudo bash scripts/restore.sh --root /opt/license-center-restored --config /root/restore.json --bundle /backups/center.lcb2 --accept-stale-state
# 无人值守在此基础上加 --non-interactive
```

它会：环境/端口/空间检查→相同应用及schema检查→构建镜像→两路认证解密→数据库hash/integrity/外键及加密材料预检→恢复到新目录→还原独立key目录→清空旧管理员会话→启动→数据库/API/管理页/公钥检查→隔离授权闭环自检。任何步骤失败均不会用旧备份覆盖既有生产数据。失败的半成品目录保留用于诊断，重试使用新的空目标目录，不会静默清空重试。

恢复保留原issuer、签名身份、许可证管理密钥与实例密钥摘要和权益时点。原客户凭据应继续工作；已测试加密恢复后原实例刷新，这不等于已完成实际跨物理服务器Docker验收。管理会话故意失效，管理员用原密码+MFA重新登录，不创建新默认账号。

## 切换与回退

最终备份前隔离旧机写入口并确认编排器不会自动拉起。新机先通过SSH隧道验证，再切稳定域名DNS/TLS；观察刷新失败率、延迟、租约及新兑换。不能同时让两台SQLite主机接受兑换或续费。

没有新写入时，可隔离新机后回切旧机；新机已发生写入时，必须先停写新机、备份当前数据，再以最新可信状态恢复回退目标。不能简单启用旧DB把新兑换/续费/撤销抹掉。原服务器损坏、DB损坏、vault遗失与key泄露分别按原运维文档处置，key泄露不是普通迁移。

## 旧备份之后的数据

当前没有WAL连续异地归档或通用自动增量重放，恢复旧快照不能承诺零丢失。优先寻找更近的可信备份或幸存完整DB；对账工具 `python -m center.cli --data <较新数据目录> reconcile --other-data <旧恢复数据目录>` 只报差异，不擅自合并数据。需要独立订单、支付事件或可信账本佐证后才能人工修复缺失段；若证据均丢失，必须暂停相关交易并人工核对。默认RPO/RTO仍是需真实定时备份及演练支持的运维目标。

## 当前验证与待验

已验证：双口令分别加密、错误口令和篡改拒绝、拒绝覆盖已有目标、恢复原key及实例密钥后可刷新、重复初始化不改变签名身份。已提供真实Docker CI演练，覆盖首次安装、MFA、激活、重建、相同schema指定提交重部署及第二个隔离目录恢复；工作流未成功运行前一律标为待验。没有可用服务器时，不伪称已完成干净新服务器跨机验证。
