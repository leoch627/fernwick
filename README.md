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
| `updatePublicKey` / `policyPublicKey` | 两把不同的签名公钥，见下文 |

```sh
npm run brand -- config/brand.json          # 生成 work/build-config.json
export STARRAIL_BUILD_CONFIG=work/build-config.json
npm run core:fetch -- darwin-arm64           # linux-x64 / win32-x64 / darwin-x64 / darwin-arm64
npm run native:build -- --target darwin-arm64
npm run build && npx electron-builder --config electron-builder.cjs --mac dmg zip --arm64
```

## 更新端点（Cloudflare Worker + R2）

1. 生成两对密钥（放在仓库之外）：
   ```sh
   npm run policy -- generate-key ~/keys/release
   npm run policy -- generate-key ~/keys/policy
   ```
2. Cloudflare 创建 API Token（权限：Workers Scripts 编辑、Workers R2 Storage 编辑），记下 Account ID。
3. GitHub 仓库 Settings → Secrets and variables → Actions：

   | Secrets | 内容 |
   | --- | --- |
   | `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` | 上一步 |
   | `RELEASE_SIGNING_KEY` / `POLICY_SIGNING_KEY` | `~/keys/*/private.pem` 全文 |
   | `UPDATE_ADMIN_TOKEN` | 任意长随机串（`openssl rand -hex 32`） |

   | Variables | 内容 |
   | --- | --- |
   | `BRAND_ID` / `BRAND_NAME` | 同品牌配置 |
   | `BRAND_API_PRIMARY` / `BRAND_API_BACKUP` | 主备 API |
   | `BRAND_WEBSITE`、`BRAND_APP_ID`、`BRAND_SUBSCRIPTION_ORIGINS` | 可选 |
   | `UPDATE_ENDPOINT` | Worker 地址，如 `https://v2board-client-updates.<账号>.workers.dev` 或自定义域名 |
   | `UPDATE_PUBLIC_KEY` / `POLICY_PUBLIC_KEY` | `~/keys/*/public.pem` 全文 |
   | `R2_BUCKET` | 可选，默认 `v2board-client-files` |

4. Actions → **Update endpoint** → action 选 `deploy`。之后打开 `UPDATE_ENDPOINT` 就是下载页。

端点接口：`/v1/release`（签名更新索引，每 6 小时重签）、`/v1/policy`（签名策略，携带规则更新）、`/files/...`（支持断点续传）、`/`（下载页）、`/admin/*`（仅 CI 使用，需要 `UPDATE_ADMIN_TOKEN`）。

## 发布

```sh
npm version 0.2.0 --no-git-tag-version   # 改 package.json 版本并提交
git tag v0.2.0 && git push origin v0.2.0
```

**Release** 工作流会检查、四平台打包、创建 GitHub Release、上传 R2 并登记新版本，已安装的客户端会收到更新。也可以在 Actions 里手动运行 Release，临时填写其他机场名和 API 出包；勾选 `publish_endpoint` 才会推给现有用户。

- **规则更新**：Actions → Update endpoint → `rules`，或等每周一自动运行，会把最新的 Loyalsoldier/clash-rules 转换后下发。
- **代码签名**：CI 目前不做 Windows/macOS 代码签名。客户端在这两个平台检测到新版本时会打开下载页，由用户手动安装；Linux 可以在客户端内直接更新。以后接入 Windows 证书或 Apple Developer ID 签名公证，并在打包时设置 `SIGNATURE_IDENTITY`（Windows 为证书 Subject，macOS 为 Team ID），这两个平台也能在客户端内更新。

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/` | Electron 主进程、界面、领域逻辑 |
| `native/helper/` | Go 原生服务 |
| `server/` | 更新端点 Worker |
| `tools/` | 构建、品牌、签名、发布脚本 |
| `docs/` | 需求、架构、API 合同、运维说明 |

验收进度见 `docs/acceptance-status.md` 和 `support-matrix.json`；四个平台都还没有完成实机验收。
