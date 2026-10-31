# 本轮：仅编译，测试留给用户

用户最新要求：先做功能，不运行测试。本轮没有执行 npm test、核心/下载/UI/Electron 冒烟、安装、TUN 接管或升级演练。

已执行编译：TypeScript tsc --noEmit；Electron/React 构建；Go helper 的 Linux x64、Windows x64、macOS x64/arm64 交叉编译。Linux DEB 与 Windows NSIS 安装包已生成；详见 build-status.json 和 work/delivery/交付说明.md。Schema 导出是构建产物生成，不表示运行测试通过。

以下保留上一版历史记录，仅供追溯，不适用于新增原生实现或当前安装包。

---

# 历史验证记录（上一版）

日期：2026-10-31（JST）。执行环境：Linux 云环境，Node.js 24.19.0，Electron 45.2.1，TypeScript 5.9.3，Vite 7.3.7，Vitest 5.0.5。该环境不是四个发行目标的实机集合。

| 验证 | 结果 | 实际范围 |
| --- | --- | --- |
| `npm run typecheck` | 通过 | 应用、服务、共享模型、工具与测试的严格 TypeScript 检查 |
| `npm test` | 13 文件，129 测试全部通过 | 确定性夹具与故障注入；不使用真实账号或真实 TUN |
| `npm run build` | 通过 | main/preload/worker CommonJS bundle 和本地 Renderer 资源 |
| `npm run schemas` | 通过 | build/policy/account/release/rules JSON Schema 从运行时定义生成 |
| `npm run config:check` | 通过 | StarRail 开发配置；不等同线上部署确认 |
| `npm run release:check` | 按预期拒绝 | 正式配置、原生组件与四目标验收不齐全，不能正式打包 |
| `npm run test:ui` | 通过 | Chromium：预览标识、连接失败提示、搜索/选择节点、模式切换、自动连接设置、暗色、480px 布局、公告纯文本、流量隐藏、下载/暂停/继续/重试/取消/安装拒绝；无 pageerror |
| `node tools/electron-smoke.mjs` | 通过 | 真实 Electron 进程：sandbox preload IPC、Worker 解析、示例同步，Renderer 无 require/process；UI 不泄露测试 token/节点 UUID；拒绝假连接 |
| `node tools/packaged-smoke.mjs` | 通过 | 打包后的 Linux Electron 可执行文件、ASAR 本地界面、IPC；拒绝 `--demo` 和开发 URL 环境开关；初始显示真实登录表单；包内 Xray/许可证/规则/规则源码哈希及核心实际版本一致 |
| Linux DEB 构建 | 通过 | `starrail-network-dev`，amd64，0.1.0；包名/desktopName 与正式版隔离 |
| DEB 元数据/权限检查 | 通过 | 主程序 0755、ASAR/desktop/locales 0644；没有 world-writable 条目；安装包中含 Electron/Chromium 许可 |
| `npm audit --omit=dev --audit-level=high` | 通过，0 漏洞 | 锁文件的生产依赖审计快照；不能代替应用安全审计 |
| 完整 `npm audit` | 15 moderate，0 high / 0 critical | 剩余在 electron-builder 的开发打包依赖链；没有盲目执行会降级主工具的 audit fix |
| 实际面板网络访问 | 阻塞 | 配置的出口代理对面板域名 CONNECT 返回 403；未发送真实账号密码 |
| `npm run test:core` | 通过 | 官方 Xray 26.10.29：五类出站、完整 TUN 模板和整套内置大陆规则加载；抓取默认 ClientHello 确认 X25519 key share；本地真实 Shadowsocks 加密转发、SOCKS 随机会话认证、HTTPS 证书/状态/响应哈希、备用目标、取消；没有启动 TUN |
| `npm run test:download` | 通过 | 真实本地 TLS/HTTP：验签索引、流式暂停、Range + 强 If-Range 续传、精确字节/哈希、文件篡改拒绝、重定向不跟随、无账号凭据、未受信证书拒绝；不执行安装 |
| `npm run rules:import` | 通过 | 原始数据可复现与固定 baseline 相同的 SHA-256：109,628 后缀、558 精确域名、10,012 CIDR；独立 Python 标准库转换 |
| 真实 TUN/DNS/UDP/IPv6、四目标安装升级 | 未执行/未完成 | 该历史版本尚未实现原生组件；现已实现，但本轮按用户指示不测试 |

共享用例分组：

- 核心配置 9：仅认证回环探测、解析后地址保留 TLS 身份、物理绑定、DNS 不回退、全局模板、非法参数以及无效 CIDR/域名规则拒绝。
- 探测协调器 5：每批十项/四并发/冷却、超限/未知节点拒绝、注销取消迟到结果、演示拒绝和失败展示。

- 授权/时钟 13：启动门禁、期限不能后移、账号隔离、限制优先级、未知期限、参数关系和时钟回拨。
- 订阅/编译 20：空/HTML/损坏拒绝、节点隔离、不兼容列表、身份哈希、协议安全参数、节点上限、DNS/LAN/最终代理顺序；默认 X25519 配置及显式指纹优先。
- 策略 9：坏签名、环境、同版冲突、回滚、原子水位、过期、维护时间、禁止字段、URL 精确匹配、生产拒绝。
- 同步 14：主备重读、429/会话错误不切换、订阅恢复一次、注销和迟到结果、串行合并、20 秒预算、写盘失败。
- 网络状态机 7：无 helper 拒绝、健康条件、策略取消、用户断开、有界超时、恢复失败和正确清除意图。
- 存储/面板 10：密文、内存模式、锁定保留、并发清除、诊断字段边界、分支字段语义、无损字节、身份/登录重放/订阅 URL。
- 更新/选择/资源 10：签名用途、平台、撤回、水位、SemVer、下载前提、手动不换节点、自动并发/总数、端点粘性/熔断、坏资源不覆盖。
- 下载 14：实际文件偏移续传、Range 退化为 200、错误状态/重定向、范围错误、错哈希/超长、撤回、磁盘不足、不可信来源、七天清理、软链接拒绝；切换产物时取消排队下载和磁盘检查中的撤回。
- 生命周期 5：通知阈值去重、重启/时区等价、续费新事件、账本保存失败和失效会话；接口变化两秒防抖及 TUN 排除；OS 数字版本比较。
- 资源协调 7：独立控制策略、耐久恢复、过期回退、ID/版本历史、迟到响应、写盘失败、缓存篡改和非法源。
- 控制器生命周期 6：网络事件合并、手动断开优先、休眠/恢复一次、休眠注销、醒来权益限制、退出先清理网络。

Electron/Chromium 自动化只在云端测试进程使用 `--no-sandbox` 和 headless Ozone。正常启动没有这些参数；实机 sandbox、钥匙串、托盘和 OS 授权仍待目标系统验收。截图时间区域使用 Asia/Tokyo；真实应用按本机时区展示。

DEB 在云端只完成构建、包内容检查以及对应打包可执行文件启动；**没有把它安装到真实 Ubuntu GNOME 机器，也没有验证其安装脚本、卸载或升级闭环**。

最初构建遇到云端套接字与 home 缓存写权限限制，已改用 Node 的 tsx loader 和工作区内构建缓存。没有关闭 TLS 验证、绕过目的域网络策略或要求用户关闭系统安全功能。

实际核心验证仅证明 Linux x64 上的配置与本地 TCP/TLS 转发。REALITY、VMess、Trojan 的该次测试只覆盖配置加载；没有真实远端协议握手，也没有真实 TUN、UDP、DNS 或 IPv6 流量证据。两个线上健康目标在当前出口策略下同样无法访问，其线上故障域与状态合同仍需发行验收。

真实握手抓取仅在回环测试服务中读取 TLS ClientHello 的 key_share 扩展，忽略 GREASE 后为组 29；没有抓取用户流量。默认 profile 的 Supported Groups 仍包含其他兼容曲线，因此这一结果证明初始 X25519 key share，不声称任意远端的最终协商结果。
