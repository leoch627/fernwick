# 构建、签名与运营

## 配置边界

`config/development.json` 是开发配置（test 渠道）。正式包用 `npm run brand` 从品牌文件或 CI 变量生成 `work/build-config.json`（production 渠道），字段说明见 README「品牌配置」。主备 URL 和所有可信来源都在构建时写入 `dist/build-config.json`，打包后不能经命令行或环境变量更换 API。

修改订阅来源必须是明确允许的精确 origin；不允许替换订阅 host 拼接 token。路径、端口、scheme、userinfo 和转义均经过检查。

```sh
npm run config:check -- config/development.json
npm run brand -- config/brand.json
STARRAIL_BUILD_CONFIG=work/build-config.json npm run build && npm run release:check   # 检查的是 dist/ 里实际要打包的配置
```

## 策略与发布索引

运行时、测试、工具使用同一 Zod Schema。`npm run schemas` 生成可供编辑器使用的 JSON Schema；字段之间的关系仍要由完整运行时校验器检查。

Ed25519 签名覆盖用途前缀、换行和原始 UTF-8 JSON bytes：

- 策略：`v2board-client-policy-v1`
- 发布索引：`v2board-client-release-v1`

信封字段为 `keyId`、无 padding base64url `payload`、`signature`。签名不对 JSON 重新序列化。拒绝重复 key、不安全整数、未知字段、错误环境/渠道、过期、降序号、同序号不同字节以及包外来源。

一把 Ed25519 密钥同时签策略和发布索引（签名带用途前缀，两者不能互相冒充）。正常发布由 `server/` 自动签名，下面的命令只用于手工签名排查。密钥目录放在仓库之外，私钥权限 0600：

```sh
npm run sign -- generate-key /secure/signing
```

客户端仅写入公钥。不要将签名私钥、平台证书或真实凭据提交仓库、测试夹具、安装包或普通日志。

```sh
npm run sign -- sign policy payload.json /secure/signing/private.pem envelope.json
npm run sign -- verify policy envelope.json config/your-build.json
npm run sign -- sign release index.json /secure/signing/private.pem signed-index.json
npm run sign -- verify release signed-index.json config/your-build.json
```

命令不会输出密钥内容。`sign` 是签名工具，完整跨字段、环境、来源、期限验证需要随后运行 `verify`，现存发布序号还需对发布记录比较。

策略参数只允许在 Schema 范围内变更；完整同步周期 × 1.1 + 80 秒必须小于缓存窗口。远程不能下发脚本、raw Xray、动态执行文件、关闭 TLS、强制升级字段或信任根。

本地策略激活记录将签名信封和水位一起写盘。过期不删除水位；注销不清理公共水位。同版同内容幂等，不能续命；回退内容必须使用更高版本签名。

## 内置和远程规则

`resources/rules/manifest.json` 记录固定的 Loyalsoldier/clash-rules 提交、原始数据及转换结果哈希。运行 `npm run rules:import` 可用 Python 标准库复现完整 baseline；构建过程也会复核文件哈希和运行时 Schema。变更基线必须作为新的应用构建审核、更新 manifest 并重新测试，不能就地覆盖固定哈希的文件。

远程策略只指向白名单来源中的精确资源，下载调度不会阻塞控制策略生效；新规则须校验并持久化后激活，失败时使用有效旧规则或内置数据。ID 不能绑定不同字节，版本不能降序，历史随缓存保存。独立资源最大 32 MiB；域名/IP 数量限制见 rules.schema.json。当前生产规则源未配置，应用使用随包基线。

更新下载由用户点击开始，因为当前没有可靠计费网络/电池状态判断。支持单槽下载、暂停/续传/取消/重试、启动与周期清理。撤回或不兼容时清除待下载文件；安装前重新取得有效签名索引。用户确认安装后由原生服务独立复验，并交给平台更新进程备份、安装和故障恢复；本轮未运行安装验收。

## 实际部署流程（待接入发布基础设施）

1. 完成 runtime 校验并提高 policyVersion/releaseSequence。
2. 在受控环境签名；平台安装包另外代码签名/公证。
3. 上传按 SHA-256 命名的不可变规则与安装产物，核对长度、哈希、来源和四目标文件。
4. 原子更新可变 current/index 指针，CDN revalidate、最大陈旧窗口 60 秒。
5. 在预发布客户端做故障切换、过期、撤回和 N→N+1 完整安装验证，再推广到正式源。
6. 策略至少每日巡检，剩余不足 48 小时以新版本续签；更新索引至少每 12 小时新序号续签，默认有效 24 小时。
7. 由运营方设置任务责任人、失败告警、密钥访问控制和更新记录。

本工程没有部署对象存储/CDN，没有上线这些巡检任务，也未接入真实安装器。不要把提供签名工具理解成远程发布已经完成。普通更新不得因下载完成就自动安装；安装前须重新验证当前有效索引、撤回状态和网络清理成功。

## 第三方许可

运行 `npm ci` 后锁文件确定依赖版本。Electron MIT、React MIT、Zod MIT、semver ISC，开发构建工具各有自己的许可。Xray-core 26.10.31 为 MPL-2.0，开发包包含对应目标未经修改的上游二进制；来源、归档及可执行文件 SHA-256 固定在 resources/core-lock.json，许可和对应源码链接随包分发。大陆规则数据及独立转换脚本单独以 GPL-3.0 分发，原始数据、许可证、修改日期和可复现脚本随源码与二进制包附带。真实发布前仍须补齐 helper、平台组件及实际依赖库存的告知与来源。见 `THIRD_PARTY_NOTICES.md`。
