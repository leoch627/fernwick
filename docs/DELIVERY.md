# StarRail Network 开发版交付

当前桌面入口为 Wails v3 + Go，界面继续使用 React/Vite。迁移进度与本轮验证记录见 `wails-migration.md` 和 `verification.md`；此前 Electron 版本的测试记录不能作为 Wails 实机验收证明。

## 功能实现

- 登录、套餐/到期/流量展示、主备 API、订阅同步、缓存授权、节点选择、规则/全局、通知、设置、系统浏览器续费及本地诊断。
- Windows 服务、macOS launchd 服务、Linux systemd 服务；连接与修复按钮调用实际原生实现。Unix socket/Windows named pipe 校验进程身份；客户端先验证安装时生成的 Ed25519 服务身份，再发送秘密。界面只接收脱敏视图，并通过受限 Command 桥接发出操作；生产前端编入 Go 可执行文件，helper 固定校验应用哈希。
- 固定 Xray 26.10.31；四目标 helper；Windows Wintun DLL 与许可证来自同一固定哈希的官方 Xray 归档。默认 hellochrome_120 提供 X25519 初始 key share，订阅显式有效指纹优先。
- 服务内部编译受限配置，通过 stdin 启动核心。Linux 使用 nftables、策略路由和 resolved；macOS 使用 PF anchor、utun 路由及比较后恢复 DNS；Windows 由 Xray 持有适配器路由/DNS/WFP，服务管理临时防火墙保护。
- 准备、保护、启动、TCP/UDP/DNS/IPv6 证明、提交和清理；用户/进程所有权、心跳、核心监督、进程出生标识、恢复日志、服务重启恢复、物理接口绑定、控制 API 的物理 HTTPS 通道。路由/DNS 变化轮询触发受控恢复。
- 隔离节点探测使用父进程绑定且限时的工作进程；正式连接仍需实际数据路径证明，不模拟连接成功。
- 签名策略、独立规则更新、签名发布索引、暂停/续传下载和哈希复验。独立原生进程安装更新；Windows 验证 Authenticode，macOS 验证签名身份与 Gatekeeper，Linux 校验签名索引与 DEB 元数据；保留上一份备份并记录中断恢复状态。
- 系统安装/卸载钩子、离线修复命令、四目标构建和原生签名流水线。退出账号时尝试移除本次远端会话，本地秘密立即清除。

## 固定配置

品牌 StarRail Network；主 https://api.starrail.work、备 https://host.leiterup.de，按用户说明视为同一面板的入口。适配 wyx2685/v2board 提交 cfabf395644b68c318751439e8510093cd3aaeb2，订阅格式 v2ray-uri-base64-v1。官网、续费和帮助使用面板根页面。

开发配置允许试连已实现的五类协议，仍保留 nodeCapabilitiesConfirmed=false，不虚构服务端能力确认；连接提交前进行实际 TCP/UDP/DNS/IPv6 检查。生产配置禁止此试连开关。

## 编译与交付

Go helper 已编译为 Linux x64、Windows x64、macOS x64/arm64，React 资源已编入桌面主程序。本轮在 macOS arm64 构建机生成了两个 macOS 架构的 DMG/ZIP 和 Windows x64 NSIS，并通过签名完整性及资源哈希检查。产物位于 `release/`，通过 `node tools/release-assets.mjs manifest <target>` 生成大小、哈希和核心版本记录。Linux DEB 构建由 Ubuntu 24.04 CI 执行，本机未生成 Linux 桌面程序。

本轮已运行前端、Go 核心及打包相关检查，具体结果以 `verification.md` 为准。真实账号、TUN 接管、目标系统安装升级和故障恢复仍须逐平台验收。

## 待接入资料

真实账号、节点和目标系统由用户自行测试。此前云环境对面板域名的 CONNECT 请求被出口策略拒绝，这一历史结果不代表当前面板状态。

运营策略/规则发布源、更新发布源、公钥、代码签名和公证身份尚未提供，配置保持为空。代码已接入相应流程，不生成假的发布服务或把临时私钥当作正式信任根。配置见 operations.md 和 native-service.md。

此 V2Board 分支的 removeSession 不清除 JWT 用户缓存，远端失效可能受其 3600 秒缓存影响；桌面端立即清除本地秘密。详见 api-contract.md。
