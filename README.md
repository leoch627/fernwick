# StarRail Network

按附件 V2Board_Xray.md 实现的 Electron + TypeScript + Xray 桌面客户端，品牌 StarRail Network。主 API 为 https://api.starrail.work，备用 https://host.leiterup.de；适配 wyx2685/v2board 的固定提交。

本轮已接入实际原生连接、系统服务安装/修复、路由/DNS/防火墙、心跳与恢复、更新安装和回退功能。按用户要求，本轮只编译打包，没有运行测试。交付为待用户测试的开发版，不能把编译成功当作实机验收通过。

默认使用 X25519 初始密钥交换：未指定指纹时使用固定 Xray 支持的 hellochrome_120；订阅中明确指定的有效指纹保留。不会把无效的 x25519 字符串填进 fingerprint。

## 构建

需要 Node.js 24、Python 3、Go 1.27.3。Linux 示例：

```sh
npm ci
npm run core:fetch -- linux-x64
npm run native:build -- --target linux-x64
npm run build
npm run package:test
```

核心下载和原生构建目标可替换为 win32-x64、darwin-x64、darwin-arm64。Linux 使用 DEB，Windows 使用 npm run package:windows，macOS 使用 npm run package:macos 生成 DMG/ZIP。实际连接请安装完整包，GUI 使用普通用户运行；首次连接/修复会调用系统权限流程。macOS 应放入 /Applications。

npm run dev 用于源码界面与业务调试；npm run demo 是明确标识的示例模式，不模拟代理成功。真正的系统服务只授权已安装且身份匹配的应用。手动四目标打包流程位于 .github/workflows/package-development.yml。

## 功能

- 登录、套餐/到期/流量、续费、串行同步、主备 API、严格订阅解析、加密缓存与授权期限。
- 中文界面、规则/全局、自动/手动节点、节点探测、到期通知、主题/启动设置及本地诊断。
- Go 原生服务：Linux systemd、macOS launchd、Windows service；受限 IPC、双向身份确认、机器级所有权、实际 Xray TUN、DNS/UDP/IPv6、恢复日志和离线修复。
- 固定大陆直连规则、独立签名策略/规则更新、签名更新索引、暂停/续传、保护目录复验、平台安装器、备份和中断恢复。
- 四目标固定核心/helper，Windows Wintun DLL。原生签名流水线保留签名前后哈希，防止签名改变二进制后无法运行。

运营策略/更新发布地址、公钥和平台证书尚未配置，相关代码保留真实接入入口。生产发布仍需配置和用户验收，不生成假的发布服务或测试通过结果。

## 交付与文档

交付产物在 work/delivery；安装包清单以交付说明.md 和 SHA256SUMS.txt 为准。源码压缩包不包含 node_modules 或二进制缓存，原生组件另附压缩包。

- docs/DELIVERY.md：本轮实现、编译与接入边界。
- docs/native-service.md：构建、原生签名、安装和离线修复。
- docs/user-guide.md：客户端使用。
- docs/api-contract.md：固定 V2Board 合同。
- docs/operations.md：运营策略与更新发布。
- docs/acceptance-status.md、support-matrix.json：待用户测试的验收追踪。
- docs/verification.md：本轮编译记录与明确隔离的历史测试记录。

原始需求保留在 docs/requirements.md。测试源码仍保留，但本轮没有执行 npm test、UI/核心冒烟、真实网络接管或安装升级测试。
