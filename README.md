# V2Board 桌面客户端

Wails v3 + Go + React + Xray 的 V2Board 桌面客户端，支持 Windows 11 x64、macOS 14+（Apple 芯片 / Intel）和 Ubuntu 24.04 x64。面向中国大陆网络下的普通用户：下载、安装、打开、选线路、连接，其余全部自动。机场名称、主备 API 都在打包时提供，同一份代码可以给不同机场出包。配套的自建端点（`server/`，一个 Go 程序）负责自动更新、远程规则、安装包下载页和遥测。

- 一个窗口：登录、连接按钮、线路、套餐；其余放在设置里。出错时给一句人话和下一步按钮
- Xray 随包，规则随包，连接时不从 GitHub / Cloudflare 下载任何东西
- 分流照搬运营方的 Mihomo 模版（v2fly geosite/geoip）：广告拦截，AI 不走港澳节点，Apple/Steam/B 站直连，国内直连，其余走代理
- 「自动选择」由 Xray 内置测速负载均衡完成，节点挂了自动切换；AI 流量自动走最快的美日新等节点
- 主备 API 和主备端点自动切换；面板 API 连不上时，上次同步的线路最多再用 7 天（不超过套餐到期）
- 遥测：连接结果、失败步骤、错误码、各域名可达性，带用户邮箱；「上报问题」附网络自检并给出 6 位问题编号
- Go 原生服务（systemd / launchd / Windows 服务）接管 TUN、路由、DNS，崩溃与断电后可恢复
- 签名更新索引与签名策略（Ed25519），远程规则更新，断点续传下载

## 开发

需要 Node.js 24、Python 3、Go 1.27.3（Go 模块最低 1.26）。macOS 安装 Xcode Command Line Tools；Ubuntu 24.04 安装 `libgtk-3-dev libwebkit2gtk-4.1-dev`。Windows 使用系统 WebView2；生成安装器还需要 NSIS（`choco install nsis`）。

```sh
npm ci
npm run dev        # 源码运行（config/development.json）
npm run demo       # 示例数据界面，不连接网络
npm run check      # 类型检查 + 单元测试 + 构建
cd native/helper && go test ./...
```

桌面入口位于 `desktop/`，React 通过 Wails Bridge 调用 Go 协调器。`npm run build` 生成内嵌前端与配置，`npm run dev/demo` 启动 Wails。Linux 构建显式使用 `gtk3` tag，以匹配 WebKitGTK 4.1；直接运行 Go 时也要加上 `-tags gtk3`。迁移细节和实测状态见 `docs/wails-migration.md`。

会话改用系统钥匙串中的随机密钥和 AES-256-GCM，保存为 `session.v2.enc`。旧 Electron `session.enc` 不迁移，首次启动需要重新登录；偏好目录保持原位置。

```sh
npm run check:desktop         # Go 静态检查和竞态测试
npm run fixtures:wails:check  # 与保留的 TypeScript 实现核对 schema、节点 ID 和探测配置
npm run test:ui               # 浏览器预览交互（STARRAIL_TEST_CHROMIUM 指定 Chrome 路径）
npm run test:core             # 显式运行固定 Xray 的 Go 网络探测 smoke
npm run test:download         # 显式运行 Go TLS 下载 smoke
npm run test:packaging        # 安装器资源/恢复约束检查
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
| `endpoint` | 自建端点地址，可以是数组：第一个是主域名（CI 发布到这里），其余是指向同一台服务器的备用域名 |
| `publicKey` | 签名公钥（`public.pem` 全文），见下文；CI 打包不用填，自动从 `SIGNING_KEY` 计算 |

```sh
npm run brand -- config/brand.json          # 生成 work/build-config.json
export STARRAIL_BUILD_CONFIG=work/build-config.json
npm run core:fetch -- darwin-arm64           # linux-x64 / win32-x64 / darwin-x64 / darwin-arm64
npm run native:build -- --target darwin-arm64
python3 tools/package.py --target darwin-arm64
```

打包目标为 `darwin-arm64`、`darwin-x64`、`win32-x64`、`linux-x64`。macOS/Linux 在相应系统上构建；Windows 可交叉编译。产物位于 `release/`，Go 可执行文件位于 `dist/desktop/<target>/`。打包前会核对品牌配置与 helper 的构建 ID，并在签名后复核核心、helper、规则及许可证哈希。macOS 默认 ad-hoc 签名；`STARRAIL_MAC_SIGN_IDENTITY` 可指定签名身份，公证仍需发布环境另行完成。

## 更新端点（自建）

端点是 `server/` 里的一个 Go 程序，部署在你自己的服务器上（Cloudflare 在大陆不稳定）。部署步骤见 [server/README.md](server/README.md)。

整套只需要一把签名密钥（`SIGNING_KEY`）：端点用它给更新索引和规则策略签名；CI 打包时从它算出公钥内置进客户端；调用端点管理接口的令牌也从它推导（`node tools/admin-token.mjs private.pem`）。

1. 生成密钥，写进 GitHub（私钥只进 Secrets，`~/keys/signing` 留作备份）：
   ```sh
   npm run sign -- generate-key ~/keys/signing
   gh secret set SIGNING_KEY < ~/keys/signing/private.pem
   ```
2. 按 server/README.md 部署端点，把同一份 `private.pem` 放到服务器上。
3. GitHub Variables 填品牌：`BRAND_ID`、`BRAND_NAME`、`BRAND_API_PRIMARY`、`BRAND_API_BACKUP`、`UPDATE_ENDPOINT`（多个域名用空格分隔，第一个为主），可选 `BRAND_APP_ID`、`BRAND_WEBSITE`、`BRAND_SUBSCRIPTION_ORIGINS`。

端点接口：`/v1/release`（签名更新索引，每 6 小时重签）、`/v1/policy`（签名策略，携带规则更新）、`/files/...`（支持断点续传）、`/`（下载页，附未签名安装包的打开说明）、`/v1/telemetry`、`/v1/report`（客户端遥测和问题报告）、`/admin/`（按邮箱或问题编号查用户情况的页面）、`/admin/*`（CI 上传和发布）。

## 发布

```sh
npm version 0.2.0 --no-git-tag-version   # 改 package.json 版本并提交
git tag v0.2.0 && git push origin v0.2.0
```

**Release** 工作流会检查、四平台打包、创建 GitHub Release、上传到自建端点并登记新版本，已安装的客户端会收到更新。也可以在 Actions 里手动运行 Release，临时填写其他机场名和 API 出包；勾选 `publish_endpoint` 才会推给现有用户（端点只接受同一个 `id`，换 `id` 的包需要单独部署端点）。

- **规则更新**：Actions → Update endpoint → `rules`，或等每周一自动运行，会用最新的 v2fly geosite/geoip 按 `tools/import-rules.py` 里的分段顺序生成规则并下发。客户端约 15 分钟内拉到新规则，正在连接的会自动按新规则重连。分段顺序和去向在脚本开头，改分流就改那里。随包规则用 `python3 tools/import-rules.py build` 按 `resources/rules/manifest.json` 里固定的数据版本重新生成。
- **自定义规则**：编辑 `config/rules-extra.json` 并提交到 main，会自动重新发布规则（需要已部署端点）。`proxyDomains` 强制走代理，`blockedDomains` 屏蔽，`directDomains` 额外直连；这三项都匹配域名及其子域名，`directFullDomains` 只匹配完整域名，`directIPs` 写 IP 或 CIDR。它们排在所有生成规则之前，优先级：屏蔽 > 强制代理 > 直连。只对远程规则生效，随包规则不受影响。
- **端点程序**：Actions → Update endpoint → `build` 编译 Linux amd64/arm64 二进制，下载后按 server/README.md 替换。
- **代码签名**：CI 目前不做 Windows/macOS 代码签名。客户端在这两个平台检测到新版本时会打开下载页，由用户手动安装；Linux 可以在客户端内直接更新。以后接入 Windows 证书或 Apple Developer ID 签名公证后，这两个平台也能在客户端内更新：打包脚本直接从签好的安装包读出证书 Subject / Team ID 写进更新索引，不需要另外填写。

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/renderer/` | React 界面、Wails Bridge 和浏览器预览 |
| `src/shared/` 及保留的 TS 逻辑 | 前端类型、构建校验和迁移对照测试 |
| `desktop/` | Wails 外壳、Go 协调器、领域/网络/存储逻辑及测试 |
| `native/helper/` | Go 原生服务 |
| `server/` | 自建端点（更新、规则、下载页、遥测），Go |
| `tools/` | 构建、品牌、签名、发布脚本 |
| `docs/` | 需求、架构、API 合同、运维说明 |

验收进度见 `docs/acceptance-status.md` 和 `support-matrix.json`；四个平台都还没有完成实机验收。

## 体积与内存验证

迁移减少了随包分发的 Chromium/Electron 运行时；是否降低空闲内存必须在同一机器、同一场景实测。当前未记录可靠的 Electron/Wails 空闲 RSS 对照，不能据此给出节省比例。安装包实测结果和平台验证限制记录在 `docs/wails-migration.md`。
