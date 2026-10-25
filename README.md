# 通用软件授权中心

**v1.1.0 已公开发布并通过 Ubuntu 24.04 x86_64 验收**：[发布与一键命令](https://github.com/huang199800/license-center/releases/tag/v1.1.0)、[CI记录](https://github.com/huang199800/license-center/actions/runs/40209354049)、[部署入口](docs/deployment.md)、[备份迁移](docs/migration.md)、[秘密管理](docs/security.md)。验证包括移除预装Docker后的官方APT安装、公开固定提交引导、首次MFA、重复安装、容器重建、跨提交升级和隔离目录恢复。Debian/ARM、真实跨服务器DNS/HTTPS切换仍待验收。不要从浮动main分支直接部署生产。

本交付包含可运行的授权中心、中文最小管理后台、Python 与 Node.js SDK、新项目和已有项目示例、迁移文件、加密备份恢复工具及自动化测试。它是可复现的单节点基线，尚不是原始清单所有第三阶段能力均已验收的生产终版。

**边界先行：**客户拥有源码、管理员权限或可修改运行环境时，可以绕过本地授权。签名保护权益真实性，不能强迫不受你控制的程序执行校验。要求更强的产品，应把关键计算、数据或服务留在你控制的后端。永久使用权也不等于永久离线：默认仍每 300 秒刷新、凭证有效 900 秒。

## 交付入口

- [方案、威胁模型与规则](docs/ARCHITECTURE.md)
- [API、SDK 与接入示例](docs/PROTOCOL.md)
- [部署、备份、迁移与故障恢复](docs/OPERATIONS.md)
- [完成范围、验收与待办](docs/ACCEPTANCE.md)
- [依赖版本与许可证](docs/DEPENDENCIES.md)

## 本地快速运行（Python 3.13，Windows PowerShell）

在本项目目录执行。当前机器实测 Python 3.13.2 / Node 24.13.0；生产需先安装 3.13 系列当期安全补丁。HTTP 仅供本机开发。

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip==26.2.2
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
.venv\Scripts\python.exe -m center.cli init --issuer urn:your-company:licenses --enrollment operator-enrollment.json
# 交互输入自选管理员密码，至少16字符；没有默认密码。
# 将 operator-enrollment.json 中的 otpauth_uri 或 totp_secret 导入验证器。
# 把该文件移入密码管理器，随后安全删除本地副本。
.venv\Scripts\python.exe -m center.cli seed --product demo
.venv\Scripts\python.exe -m center.cli public-keys --output trusted-public-keys.json
.venv\Scripts\python.exe -m center.cli serve
```

访问 `http://127.0.0.1:8000/`。使用创建的账号、密码与动态验证码登录。进入“兑换码交付”，选择 `demo-month`，再次验证后生成；同一枚动态验证码不能重复使用，需等待验证器出现下一枚。

在另一个 PowerShell 窗口运行已有项目示例：

```powershell
$env:LICENSE_URL='http://127.0.0.1:8000'
$env:LICENSE_PRODUCT='demo'
$env:LICENSE_TRUST_FILE='trusted-public-keys.json'
$env:LICENSE_DEV_HTTP='1'
.venv\Scripts\python.exe -m examples.existing_project activate
.venv\Scripts\python.exe -m examples.existing_project run
.venv\Scripts\python.exe -m examples.existing_project status
# 后台生成“续费”用途的码后：
.venv\Scripts\python.exe -m examples.existing_project renew
```

新项目 Web 示例读取相同环境变量与实例缓存：

```powershell
.venv\Scripts\python.exe -m uvicorn examples.new_project:app --host 127.0.0.1 --port 8010 --no-proxy-headers
# POST http://127.0.0.1:8010/reports 受后端功能校验保护
# GET  http://127.0.0.1:8010/data-export 保留修复入口
```

## 复现验证

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.venv\Scripts\python.exe -m pytest -q
node --test sdk-node/client.test.mjs
.venv\Scripts\python.exe -m scripts.smoke
.venv\Scripts\python.exe -m pip_audit
```

`scripts.smoke` 使用临时数据、真实 Uvicorn 子进程及 TCP，完成兑换、SDK 校验、续费、加密备份、新目录恢复、原实例刷新和撤销；为验证 MFA 重放防护，通常需等待 1–2 分钟。所有临时秘密随演练清理，控制台不打印兑换码或密码。

## 目录

```text
center/             FastAPI、事务业务、认证、签名、CLI
  migrations/       001.sql（schema v1）
  static/           中文管理界面
sdk/                Python SDK
sdk-node/           Node.js ESM SDK、TypeScript 类型声明与测试
examples/           新项目 Web / 已有项目 CLI
scripts/            真实 HTTP 部署与恢复演练
tests/              安全、并发、时间、离线、恢复测试
deploy/             TLS 网关、入口脚本、systemd 示例
docs/               规则、协议、运维、验收与依赖证据
requirements.lock   含传递依赖及发行文件 SHA-256 的运行锁
```
