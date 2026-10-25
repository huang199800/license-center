# API、SDK 与接入协议 v1

## HTTP 约定

生产仅HTTPS，JSON UTF-8，所有时间UTC Unix秒。路由版本前缀 `/v1`，完整请求模型、字段限制和响应可在服务的 `/openapi.json`、`/docs` 查看；交付包含 `openapi.json` 静态快照。请求模型禁止未知字段，类型严格检查。分页后台目前只有按产品过滤及最多500条限制，没有完整游标分页。

|接口|认证|含义|
|---|---|---|
|GET /health/live、/health/ready|无|存活与数据库就绪|
|GET /v1/public-keys|无|公钥参考；SDK不能据此自动建立信任|
|POST /v1/redeem|持有兑换码+Idempotency-Key|新建许可证并绑定首实例|
|POST /v1/activate|Bearer 许可证管理密钥+Idempotency-Key|已有许可证新增实例|
|POST /v1/renew|Bearer 许可证管理密钥+Idempotency-Key|续费码/功能升级码兑换|
|POST /v1/refresh|Bearer 实例密钥|校验服务端状态，刷新凭证及租约|
|POST /v1/check|Bearer 实例密钥|严格在线关键操作授权；不替代本地功能校验|
|POST /v1/deactivate|Bearer 实例密钥|受次数限制的自助解绑|
|POST /v1/admin/login|密码+TOTP|一小时管理员Bearer会话|
|POST /v1/admin/reauth|管理员会话+新的TOTP|120秒、一次性高风险操作授权|
|POST /v1/admin/logout|管理员会话|失效本会话|
|GET /v1/admin/inventory|管理员会话|按角色及产品过滤的资产与审计|
|POST /v1/admin/products|owner|创建/修改产品名称与版本|
|POST /v1/admin/plans|owner或产品operator|创建/修改套餐模板|
|POST /v1/admin/codes|写权限+再次验证|批量生成并一次性返回完整码|
|POST /v1/admin/codes/{id}/disable|产品写权限|停用兑换码，不撤销已兑许可证|
|POST /v1/admin/licenses/{id}/status|产品写权限+再次验证|暂停/恢复/撤销，填写原因|
|POST /v1/admin/instances/{id}/release|产品写权限+再次验证|损坏设备/迁移受控释放；请求含reason，status字段沿用通用模型但不改变许可证状态|
|POST /v1/admin/offline|产品写权限+再次验证+Idempotency-Key|首次签发离线许可证文件|
|GET /v1/admin/metrics|owner|许可证总数、有效租约数、schema|

密钥操作、管理员创建及备份恢复属于本机操作员CLI，要求系统级访问控制；没有从网页远程执行任意命令的功能。

### 首次兑换

```http
POST /v1/redeem
Content-Type: application/json
Idempotency-Key: <客户端生成并持久保存的UUID>

{"product":"demo","code":"<一次性交付的码>","customer":"customer-42","instance":"<稳定随机实例ID>"}
```

成功响应包括 `license_id`、`activation_id`、`license_secret`、`activation_secret`、`token`、`expires_at`、`server_time`、`refresh_interval`。两个密钥都是高熵Bearer凭据；只保存于客户受保护的持久目录。许可证密钥可保存在更高权限的运维存储中，普通业务进程可仅持有实例密钥；示例SDK为演示方便会保存两者。

首次兑换认证依赖兑换码的机密性。拥有完整码的人可能抢兑，不能通过幂等键或随机数解决身份归属问题；需要实名归属时，应在业务身份系统认证后由可信后端兑换，并另做客户绑定流程。多次码每个新幂等请求可独立兑换，达到次数即停。

`Idempotency-Key` 必须16–128字符，重试同操作必须保留原key；请求正文改变必须用新key。SDK首次激活会先保存pending key再发送，续费/新增实例由调用者保存key直到业务确认。服务端幂等响应加密保存；重放原成功请求返回原结果，不刷新其中旧token的有效期，客户端随后应调用refresh。

### 续费、刷新

```json
// POST /v1/renew；Authorization: Bearer <license_secret>
{"product":"demo","license_id":"<许可证ID>","code":"<续费或升级码>"}
```

```json
// POST /v1/refresh、/v1/check、/v1/deactivate
// Authorization: Bearer <activation_secret>
{"product":"demo","activation_id":"<实例ID>"}
```

## 错误语义

应用错误采用 `{"error":{"code":"LICENSE_EXPIRED"}}`；输入模型不合法采用FastAPI标准422 `detail`。SDK把未知请求错误映射为 `REQUEST_INVALID`，不会默认通过。

|类别|错误示例|业务建议|
|---|---|---|
|网络|NETWORK_UNAVAILABLE、CENTER_UNAVAILABLE、RATE_LIMIT|周期模式可用尚有效凭证；严格在线拒绝新任务；退避重试|
|尚未激活|NOT_ACTIVATED|引导合法激活，保留数据导出|
|权益|LICENSE_EXPIRED、LICENSE_REVOKED、LICENSE_PAUSED、LICENSE_NOT_YET_VALID|不自动当网络错误；拒绝新授权操作|
|凭证|TOKEN_INVALID、TOKEN_ALGORITHM、TOKEN_UNKNOWN_KEY、TOKEN_AUDIENCE、TOKEN_INSTANCE、TOKEN_TIME_INVALID|拒绝；检查信任配置/篡改/产品实例|
|凭证到期|TOKEN_EXPIRED|尝试合法联网刷新；不能延长本地exp|
|资源|DEVICE_LIMIT、ONLINE_LIMIT、REBIND_COOLDOWN、REBIND_LIMIT|按管理流程处理，租约到期后再尝试|
|兑换|CODE_INVALID、CODE_EXHAUSTED、CODE_REDEEM_EXPIRED|区分兑换资格与已兑权益|
|认证|LICENSE_AUTH_FAILED、ACTIVATION_AUTH_FAILED、ADMIN_SESSION_EXPIRED|恢复正确凭据/重新登录|
|一致性|IDEMPOTENCY_KEY_REQUIRED、IDEMPOTENCY_CONFLICT|使用正确且持久保存的key|
|管理|ROLE_DENIED、PRODUCT_DENIED、REAUTH_REQUIRED、OTP_INVALID_OR_REPLAYED|不能用前端隐藏替代服务端权限|
|本地|CLOCK_ROLLBACK、CACHE_INVALID、CACHE_SCOPE、CACHE_INSTANCE|排查时钟与缓存；不删除客户数据|

## Python SDK

```python
import json
from pathlib import Path
from sdk import LicenseClient, LicenseError

trust = json.loads(Path('trusted-public-keys.json').read_text())
client = LicenseClient(
    'https://licenses.example.com', 'demo',
    trust['issuer'], trust['keys'], 'business-state/license.json'
).initialize()
# 首次由交互入口执行 client.activate(code, customer)
client.start_background_refresh()
try:
    client.requireFeature('basic')
    # 业务数据库事务内取得可信用量，再检查并完成同一个事务内的写入。
    client.checkQuota('users', current=3, additional=1)
    # 执行业务核心操作
except LicenseError as exc:
    # 拒绝新任务或进入业务定义的只读模式，保留客户数据。
    print(exc.code)
finally:
    client.close()
```

方法：`initialize`、`activate`、`activate_existing`、`refresh`、`getLicenseStatus`、`requireFeature`、`checkQuota`、`renew`、`deactivate`、`installOffline`、`start_background_refresh`、`close`。每个业务进程持有一个client，生命周期操作应串行；多进程不能共同写同一个缓存文件，需每个实例独立缓存或在适配层实现共享锁与单一刷新代理。

`getLicenseStatus` 返回本地凭证状态，用于展示；它不会代替严格在线 `requireFeature` 的中心检查。升级/支持权限字段在签名声明中公开，但业务版本判定需要产品自己定义版本映射；当前没有SemVer发布权益引擎。

Web路由保护见 `examples/new_project.py`；已有CLI改造见 `examples/existing_project.py`。后台作业在创建新任务时调用 `requireFeature`，长期任务在安全检查点决定是否允许后续新工作。任务中途不要直接杀进程。

## Node.js / TypeScript

```javascript
import {readFileSync} from 'node:fs';
import {LicenseClient} from './sdk-node/client.mjs';
const trust=JSON.parse(readFileSync(process.env.LICENSE_TRUST_FILE,'utf8'));
const client=new LicenseClient({
  url:process.env.LICENSE_URL,product:process.env.LICENSE_PRODUCT,
  issuer:trust.issuer,keys:trust.keys,cache:process.env.LICENSE_CACHE
}).initialize();
client.startBackgroundRefresh();
await client.requireFeature('basic');
```

ESM源码使用Node标准crypto/fetch，无额外npm依赖；提供 `client.d.ts`，`sdk-node/package.json` 声明类型入口。实测Node24.13.0。异步方法与Python语义对应；新增实例方法为 `activateExisting`，后台刷新为 `startBackgroundRefresh`。JavaScript对象仅存应用配置，不适合打包到浏览器；这是Node服务端/CLI SDK。

## 离线文件

管理员先创建 `policy=offline` 的套餐：例如 `days=null, perpetual=true, token_ttl=900, refresh_interval=300, offline_max=2592000`。`offline_max` 是交付文件有效期，本例30天，而不是永久离线。先读取目标机器SDK `initialize()` 保存的稳定instance，再经产品写权限与新的TOTP调用 `/v1/admin/offline`：

```json
{"plan":"demo-offline","customer":"customer-42","instance":"<目标实例随机ID>","reason":"隔离网络交付"}
```

把响应JSON作为许可证文件通过可信渠道交付；客户端 `installOffline('offline.json')` 验证签名、产品和实例后缓存，不下载公钥，不需要实例API密钥。当前中文后台没有离线签发专门表单，可通过API调用，永久权离线文件续签工作流尚未交付。离线文件虽可在后台标撤销，未联网客户仍会用到文件到期；无法实时在线计数，克隆同一实例缓存仍存在风险。

## 后续语言适配路线和兼容政策

|语言|实现路线|交付状态|
|---|---|---|
|Python 3.13|cryptography Ed25519 + httpx + 原子缓存|可运行，自动化及真实HTTP验证|
|Node24 / TS|标准crypto Ed25519 + fetch，ESM及类型声明|可运行，自动化及真实HTTP验证|
|PHP|libsodium `sodium_crypto_sign_verify_detached`，原始32字节公钥；HTTP客户端及文件锁适配|路线，未交付SDK|
|Go|`crypto/ed25519`、`net/http`、结构体严格JSON检查、原子文件替换|路线，未交付SDK|
|Java|受支持JDK的 `Signature.getInstance("Ed25519")`、X.509 SPKI公钥与HTTP客户端|路线，未交付SDK|

其他语言按OpenAPI和相同安全断言适配，并复用错误码测试向量。不可只验证签名而漏掉aud/instance/time/status。v1保持已公布语义；增字段可能出现，客户端拒绝不支持的算法与版本。破坏性协议变更发布 `/v2` 并提供至少6个月迁移窗口；当前这是维护政策目标，尚无实际v2。SDK v1只声明兼容本交付协议v1。

纯浏览器前端无法安全保管服务端Bearer管理密钥，也不能可靠强制不受控设备执行本地授权。需要你的业务后端代为认证客户和校验授权；不要把管理员会话、许可证管理密钥或签名私钥放在前端。
