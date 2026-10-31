# V2Board 桌面客户端

Electron + TypeScript + Xray 的 V2Board 桌面客户端，支持 Windows 11 x64、macOS 14+（Apple 芯片 / Intel）和 Ubuntu 24.04 x64。机场名称、主备 API 都在打包时提供，同一份代码可以给不同机场出包。配套的 Cloudflare Worker（`server/`）负责自动更新、远程规则更新和安装包下载页。

- 登录、套餐/到期/流量、续费跳转，主备 API 自动切换，严格订阅解析，加密本地缓存
- 规则/全局模式，自动/手动选节点，节点测速，到期提醒，托盘与开机启动
- Go 原生服务（systemd / launchd / Windows 服务）接管 TUN、路由、DNS，崩溃与断电后可恢复
- 签名更新索引与签名策略（Ed25519），远程规则更新，断点续传下载

## 开发

需要 Node.js 24、Python 3、Go 1.27。

```sh
npm ci
npm run dev        # 源码运行（config/development.json）
npm run demo       # 示例数据界面，不连接网络
npm run check      # 类型检查 + 单元测试 + 构建
cd native/helper && go test ./...
```

## 品牌配置（机场名、API）

复制 `config/brand.example.json` 并填写：

| 字段 | 说明 |
| --- | --- |
| `id` | 稳定标识，小写字母/数字/连字符。决定系统路径、服务名、Linux 包名。**发布后不要改**，否则用户需要重新安装 |
| `name` | 显示名称，可用中文，可以随时改 |
| `appId` | 可选，反向域名形式，默认 `app.<id>` |
| `api` | API 地址数组，第一个为主，其余为备用 |
| `subscriptionOrigins` | 可选，订阅链接域名与 API 不同时填写 |
| `website` | 可选，官网/续费页，默认主 API 域名 |
| `endpoint` | 更新端点地址（部署 `server/` 后得到） |
| `publicKey` | 签名公钥（`public.pem` 全文），见下文；CI 打包不用填，自动从 `SIGNING_KEY` 计算 |

```sh
npm run brand -- config/brand.json          # 生成 work/build-config.json
export STARRAIL_BUILD_CONFIG=work/build-config.json
npm run core:fetch -- darwin-arm64           # linux-x64 / win32-x64 / darwin-x64 / darwin-arm64
npm run native:build -- --target darwin-arm64
npm run build && npx electron-builder --config electron-builder.cjs --mac dmg zip --arm64
```

## 更新端点（Cloudflare Worker + R2）

整套只需要一把签名密钥，也只配置一次（`SIGNING_KEY`）：Worker 用它给更新索引和规则策略签名；CI 打包时从它算出公钥内置进客户端；CI 调用 Worker 管理接口的令牌也从它推导。

1. 生成密钥，写进 GitHub（私钥只进 Secrets，`~/keys/signing` 留作备份）：
   ```sh
   npm run sign -- generate-key ~/keys/signing
   gh secret set SIGNING_KEY < ~/keys/signing/private.pem
   ```
2. Cloudflare（用托管端点域名的那个账号）：开通 R2；My Profile → API Tokens 用「Edit Cloudflare Workers」模板建 Token，并加上 Account → Workers R2 Storage → Edit。
   ```sh
   gh secret set CLOUDFLARE_API_TOKEN --body '<token>'
   gh secret set CLOUDFLARE_ACCOUNT_ID --body '<account id>'
   ```
3. GitHub Variables 填品牌：`BRAND_ID`、`BRAND_NAME`、`BRAND_API_PRIMARY`、`BRAND_API_BACKUP`、`UPDATE_ENDPOINT`，可选 `BRAND_APP_ID`、`BRAND_WEBSITE`、`BRAND_SUBSCRIPTION_ORIGINS`、`R2_BUCKET`（默认 `v2board-client-files`）。
4. Actions → **Update endpoint** → `deploy`。`UPDATE_ENDPOINT` 的域名会自动绑定为 Worker 的 Custom domain（该域名须托管在同一 Cloudflare 账号，且没有同名 DNS 记录；`workers.dev` 在大陆访问不了）。打开该地址就是下载页。

端点接口：`/v1/release`（签名更新索引，每 6 小时重签）、`/v1/policy`（签名策略，携带规则更新）、`/files/...`（支持断点续传）、`/`（下载页）、`/admin/*`（仅 CI 使用）。

## 发布

```sh
npm version 0.2.0 --no-git-tag-version   # 改 package.json 版本并提交
git tag v0.2.0 && git push origin v0.2.0
```

**Release** 工作流会检查、四平台打包、创建 GitHub Release、上传 R2 并登记新版本，已安装的客户端会收到更新。也可以在 Actions 里手动运行 Release，临时填写其他机场名和 API 出包；勾选 `publish_endpoint` 才会推给现有用户（端点只接受同一个 `id`，换 `id` 的包需要单独部署端点）。

- **规则更新**：Actions → Update endpoint → `rules`，或等每周一自动运行，会把最新的 Loyalsoldier/clash-rules 转换后下发。
- **代码签名**：CI 目前不做 Windows/macOS 代码签名。客户端在这两个平台检测到新版本时会打开下载页，由用户手动安装；Linux 可以在客户端内直接更新。以后接入 Windows 证书或 Apple Developer ID 签名公证后，这两个平台也能在客户端内更新：打包脚本直接从签好的安装包读出证书 Subject / Team ID 写进更新索引，不需要另外填写。

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/` | Electron 主进程、界面、领域逻辑 |
| `native/helper/` | Go 原生服务 |
| `server/` | 更新端点 Worker |
| `tools/` | 构建、品牌、签名、发布脚本 |
| `docs/` | 需求、架构、API 合同、运维说明 |

验收进度见 `docs/acceptance-status.md` 和 `support-matrix.json`；四个平台都还没有完成实机验收。
