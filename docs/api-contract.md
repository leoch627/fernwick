# StarRail 面板适配合同

## 基线与证据

用户指定品牌 StarRail Network，并确认 `host.leiterup.de` 与 `api.starrail.work` 是同一面板的入口。代码选择 API 子域为主、另一入口为备；两个入口的会话/授权一致性仍需部署验证。

参考源码：[wyx2685/v2board @ cfabf395644b68c318751439e8510093cd3aaeb2](https://github.com/wyx2685/v2board/tree/cfabf395644b68c318751439e8510093cd3aaeb2)。检查时间为 2026-10-31。这是**仓库合同基线**，不是断言线上服务器已经部署该提交。

重点核对 `app/Http/Controllers/V1/Passport/AuthController.php`、`app/Http/Controllers/V1/User/UserController.php`、`app/Http/Middleware/User.php`、`app/Services/AuthService.php`、`app/Services/UserService.php`、`app/Http/Controllers/V1/Client/ClientController.php`、`app/Protocols/General.php` 和 `app/Utils/Helper.php`。

`adapter-contract.json.verified` 表示上述源码接口已核对；`development.json.deploymentVerified=false` 独立表示没有线上合同验收。生产校验要求后者为 true，且不能凭源码阅读自动设为 true。

## 请求合同

| 操作 | 方法、路径 | 输入、鉴权 | 输出与语义 | 重试 |
| --- | --- | --- | --- | --- |
| login | POST `/api/v1/passport/auth/login` | JSON `email`、`password`，无旧令牌 | `data.auth_data` 为不透明账号访问凭据。`data.token` 是另一种订阅秘密，不冒充账号凭据 | 不自动跨入口重放，响应丢失交给用户重试 |
| identity / account | GET `/api/v1/user/info` | `Authorization: <auth_data>`，无 Bearer 前缀 | email、banned、plan_id、expired_at、transfer_enable；该接口没有 u/d | 幂等，按剩余总预算切备用 |
| account usage | GET `/api/v1/user/getSubscribe` | 同上 | u、d、plan、expired_at、transfer_enable、email、uuid、subscribe_url 等。**不含 banned** | 与 info 在同一入口重读并核对身份/套餐/期限/总量 |
| subscription descriptor | GET `/api/v1/user/getSubscribe` | 同上 | 保留 subscribe_url 的完整 origin、path 和原始查询参数 | 下载凭据失效时仅重新取描述一次 |
| subscription | GET 描述返回的完整 URL | URL 中的独立订阅 token；绝不附账号 Authorization | 单一冻结格式 `v2ray-uri-base64-v1` | 订阅 401/403 不等同账号 401/403 |
| restoreSession | 本地安全存储恢复后完整同步 | 同一逻辑 sessionGeneration | 不凭本地恢复延长有效窗口 | 每次冷启动尝试同步 |
| logout | 本地取消并清除密文、令牌、节点和缓存 | 无浏览器状态修改 | 此版本未调用远端会话撤销，系统浏览器登录仍可能存在 | 不伪造远端注销成功 |

未发现本客户端可依赖的 refresh-token 合同。会话明确失效后清理访问凭据并要求重新登录，不编造自动续期接口。退出账号时已接入 POST /api/v1/user/removeActiveSession，只提交当前 auth_data 中的 session 标识，最多等待 3 秒；失败不阻止本地清除。该固定分支的 removeSession 没有清除以 JWT 为键的 3600 秒缓存，因此不能承诺服务端立即撤销；客户端本地立即清除会话、订阅和节点秘密。

该分支有多种 HTTP 500 业务错误（包括错误密码、登录限流或封禁），不能将登录 500 当作可跨域重试的传输故障。登录端统一显示“登录未成功”，不盲判套餐状态。账户路径的 401/403 按冻结中间件解释为会话无效。HTTP 429 不换入口绕限流；保留 Retry-After。HTML、超限、身份不匹配及重定向均拒绝。

## 身份、日期和字节

- `user/info` 没有可直接使用的数据库 ID。当前用当前租户内的、来自服务端的规范 email 作为逻辑账户标识。email 改名要求重新登录；不把节点 uuid 当作稳定账号 ID。
- expired_at 是 Unix **秒**。在该分支的 UserService 中 null 明确允许长期有效，因此合同允许 null → unlimited。未知/缺失/0 不转成永久或 1970 年。
- u、d、transfer_enable 是字节，使用十进制字符串和 BigInt 合计。拒绝 JSON 中已经失去精度的整数。该分支零配额不是无限流量。
- info 和 getSubscribe 的 email、套餐、到期、配额不一致时，整轮失败，保留旧快照原期限。没有伪造服务端 revision 或原子快照保证。
- 账号封禁优先处理。允许使用必须有合同明确的套餐、非封禁、流量条件，有限日期到期另外阻止连接。服务器仍是最终授权执行方。

## 订阅输出

源码 `ClientController` 会在 flag/UA 非空时可能插入到期/用量“伪节点”。本客户端在已有完整订阅 URL 上设置**空的 `flag=`**：该提交把空字符串保留为 falsy，走 General.handle 的 URI/Base64 输出且不插入显示伪节点。没有根据名称关键词删除真实节点，也没有替换订阅域名。

这项选择必须在真实部署合同测试中确认；若线上分支、中间件或反向代理改变空查询参数语义，不能直接标记部署已验收。未声明额外订阅域名时会拒绝其 URL，需由开发者修改集中配置再构建。

支持解析 VLESS TCP+TLS/REALITY、VMess AEAD WS+TLS、Trojan TCP+TLS 和三种 Shadowsocks AEAD。支持该提交产生的无效应空字段。`insecure=1`、非空证书固定、ECH、未知参数及未实现的传输组合不会被悄悄丢弃。

当前 `protocolCapabilities=[]`、`nodeCapabilitiesConfirmed=false`。它们是实际能力验收结果，不是“让连接按钮变亮”的开关。待锁定核心版本并验证 TCP/UDP/双栈后才填写。

无权威空列表标志、无 ETag/304 快照复用合同。本客户端发起全量读取，拒绝裸 304 和空响应；不推断全量撤权。若账户已明确无资格，仍立即执行账号限制。

## 脱敏样例

```json
{"data":{"auth_data":"<ACCOUNT_AUTH>","token":"<SUBSCRIPTION_TOKEN>"}}
```

```json
{"data":{"email":"user@example.invalid","banned":0,"plan_id":1,"expired_at":1800000000,"transfer_enable":"214748364800","uuid":"<NODE_CREDENTIAL>"}}
```

```json
{"data":{"email":"user@example.invalid","plan_id":1,"expired_at":1800000000,"u":"1024","d":"2048","transfer_enable":"214748364800","plan":{"name":"测试套餐"},"subscribe_url":"https://host.leiterup.de/api/v1/client/subscribe?token=<SUBSCRIPTION_TOKEN>"}}
```

实际账号、令牌、订阅和节点秘密不得提交仓库。测试使用人工夹具，不称为真实账号样例。
