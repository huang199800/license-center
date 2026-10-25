# 依赖、来源及维护

核验日期：2026-10-25。版本从实施时可访问的Python包索引解析并实际安装；运行环境21个发行包的精确版本、项目官方地址及许可证元数据见 `dependency-inventory.json`。`requirements.lock`包含全部运行传递依赖和发行文件SHA-256；已在全新虚拟环境用 `pip install --require-hashes` 成功重建。开发工具另见 `requirements-dev.lock`，Node SDK没有npm依赖。

主要版本：FastAPI 0.162.0、Starlette1.10.0、Pydantic2.14.1、Uvicorn0.54.0、cryptography50.0.2、httpx0.28.1。运行时实际Python3.13.2及Node24.13.0；这并不宣称旧Python补丁没有安全问题。生产需安装3.13系列当前安全补丁并复测。

官方依据：[Python支持周期](https://devguide.python.org/versions/)、[FastAPI锁定及升级版本建议](https://fastapi.tiangolo.com/deployment/versions/)、[cryptography Ed25519接口](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/)。维护判断以当日可访问官方文档及发行包为依据，不保证未来持续维护；升级必须重新跑本交付回归和漏洞扫描。

依赖许可证包括MIT、BSD、Apache-2.0、PSF-2.0，certifi是MPL-2.0。Colorama元数据未明确声明，已核对其[官方许可证文件](https://github.com/tartley/colorama/blob/master/LICENSE.txt)为BSD-3-Clause。元数据清单和随包可取得的原许可证副本合并保留于 `THIRD-PARTY-NOTICES.txt`；源码压缩包还保留逐组件副本。没有复制商业授权系统源码；本交付自身源码未替第三方组件重新授权。再分发镜像/可执行文件时还需保留系统与运行时组件的对应声明；本项目清单不是完整操作系统SBOM。

开发虚拟环境最初的pip24.3.1被扫描报告存在已知漏洞，已升级到26.2.2后重新扫描，最终报告见 `dependency-audit.json`，扫描未发现已知依赖漏洞。它是当次数据库的结果，不等于不存在漏洞，也不包含Python解释器、操作系统、Docker/Caddy镜像或你接入的业务代码。生产构建同样固定升级pip，保留定期复扫流程。

测试工具出现一条Starlette对httpx测试传输的弃用提醒；当前测试仍全部通过。后续升级测试传输时应单独验证，不能未经兼容测试就替换业务httpx客户端。
