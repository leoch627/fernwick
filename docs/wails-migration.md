# Electron → Wails v3 迁移说明（交接文档）

目标：把桌面客户端从 Electron 45 换成 **Wails v3**，降低内存/CPU 和安装包体积。界面（React + Vite）保留，Electron 主进程的 TypeScript 逻辑改写成 Go，Go 原生 helper（`native/helper`）和 Cloudflare Worker（`server/`）基本不动。

分支：`wails-migration`。下方保留迁移设计与兼容约束；实际开发状态以本节为准。

## 当前开发进度（2026-10-31）

桌面入口和构建链已切换为 Wails v3 + Go，保留 React/Vite 界面。`desktop/core/` 包含纯逻辑、HTTP/面板/同步、加密存储、下载/规则/提醒/诊断、原生 helper 客户端、探测、网络状态机和协调器；`desktop/` 放置 Wails 窗口与系统集成。Go 模块最低版本为 1.26，CI 使用 1.27.3。

- `src/renderer/wails.ts` 通过 `main.Bridge.Command` 与 `starrail:state` 收发脱敏视图，浏览器预览仍独立运行。Electron 主程序、preload、builder 和对应 smoke 脚本已删除。
- `tools/build.ts` 生成 `desktop/frontend/dist` 和 `desktop/assets/`，随后编进 Go 可执行文件；`dist/` 保留构建配置供发布工具读取。
- `tools/package.py` 提供四个目标的原生构建与 DMG/ZIP、NSIS、DEB 打包，保留产品名称、安装目录、helper 生命周期和哈希校验。Windows 可交叉编译；macOS/Linux 需要原生 CGO 构建环境。
- macOS 包固定最低版本 14.0，同时设置 `MACOSX_DEPLOYMENT_TARGET` 和最终链接器 `-mmacosx-version-min=14.0`，避免 Wails 自带的旧链接参数让 Mach-O 的最低系统声明与 Info.plist 不一致。
- Wails 3.0.0 默认 Linux 后端是 GTK4；本项目显式加 `gtk3` tag，使用 `libgtk-3-dev libwebkit2gtk-4.1-dev`，运行依赖为 GTK3/WebKitGTK 4.1。
- helper 安装记录只固定应用可执行文件及核心身份，不再依赖 ASAR；内嵌前端由应用哈希覆盖。四个 helper 目标已用 Go 1.27.3 重建。
- 原 TypeScript 纯逻辑继续作为兼容对照及构建校验使用。固定 schema/订阅样本、Node.js 签名样本验证字段、节点 ID、探测配置和签名字节。

```sh
npm ci
npm run build
npm run demo
npm run check
npm run check:desktop
npm run fixtures:wails:check
npm run test:packaging
npm run test:core
npm run test:download
python3 tools/package.py --target darwin-arm64
python3 tools/verify-package.py release/mac-arm64 --target darwin-arm64
```

本轮已验证前端类型检查、Vite 内嵌资源构建、浏览器预览交互、安装器资源约束测试、Go 核心及下载冒烟。两个 macOS 架构的 DMG/ZIP 和 Windows x64 NSIS 已实际生成，应用签名完整性与资源哈希检查通过。macOS arm64 打包应用的原生 WebView 演示已验证账号、节点与设置页面，连接按预期返回组件不可用，未接管系统网络。完整 Go 综合验收结果见 `verification.md`。Linux 桌面/DEB 留待 Ubuntu CI；真实账号/TUN、四平台安装升级、睡眠唤醒和断电恢复尚未进行实机验收。

2026-11-01 收尾复核（macOS arm64，开发构建）：
- 修复：窗口注入脚本在 `document` 捕获阶段对 `submit` 调用了 `stopImmediatePropagation()`，React 的 `onSubmit` 收不到事件，登录表单因此无法提交（演示模式会自动登录，所以之前没暴露）。现在只保留 `preventDefault()`。
- 修复：macOS 原来在 `ApplicationDidBecomeActive` 时显示窗口，会让 `--hidden` 开机启动失效，现改为 Dock 点击触发的 `ApplicationShouldHandleReopen`；production 构建不再接受 `--demo`（与 Electron 版打包后的行为一致）；诊断导出恢复为 `<productId>-diagnostics-<日期>.json` 文件名。
- 实测：原生窗口演示模式下，账号/节点渲染正常；点击连接时如实提示组件不可用；退出登录后通过登录表单重新登录成功。
- 粗略占用（窗口打开、开发构建、RSS）：Go 主进程约 118 MB，WebKit WebContent 约 77 MB，GPU 约 47 MB，Networking 约 11 MB。RSS 里包含系统 WebKit 的共享页，不能直接与 Electron 版相加对比。

内存对照需要在同一台机器与同一场景分别测量旧 Electron 包和 Wails 包；目前没有可发布的对照数字。产物大小以实际生成文件为准，不预先填写节省比例。

后续维护约束：

- `Loop.Await` 只能在 `Run/Go` 持锁入口内调用；IO 回调不读取控制器状态，返回后重新核对 generation。各服务的独立串行锁不能在持有控制器锁时等待。
- Go `Budget.Dispose()` 取消 context；阶段切换必须使用生命周期父 context 加独立预算。
- 恢复会话前执行严格持久化校验。旧 Electron `session.enc` 不尝试解密，新文件为 `session.v2.enc`；钥匙串不可用不回退到明文。
- 节点 ID 与 connectionFingerprint 已保证 JS 序列化兼容。内部 `ContentHash` 仅保存，不承担节点选择和签名校验。
- `StrictJSON` 用 WTF-8 保留合法 JSON 孤立 UTF-16 代理项；不能用普通 JSON 重编码改变已签名负载或节点连接摘要。schema 字符串长度遵循 Zod 的 Unicode 码点规则，订阅字段和品牌名称的 JS 限制按 UTF-16 单元计数。
- Go 可信 URL 要求 ASCII/punycode 域名和标准 IPv4 点分格式；Unicode 域名与 WHATWG 旧式 IPv4 写法被拒绝。默认端口、域名大小写、点路径段、IPv6 已规范化。

---

## 1. 为什么选 Wails 而不是 Tauri

- `native/helper` 本来就是 Go，Xray-core 也是 Go。后端统一成 Go，就不用再引入 Rust 这第三种语言。
- 打包仍然沿用现有的「主程序 + resources/native/<target>/{xray,helper}」布局，helper 的身份校验只需要小改。
- Windows 上 Wails 不需要 CGO，可以从 Linux/macOS 交叉编译；macOS/Linux 需要 CGO，CI 已经在各平台原生 runner 上构建。

版本（2026-10 实测）：
- Go 模块 `github.com/wailsapp/wails/v3@v3.0.0`（2026-10-26 发布，需要 **Go ≥ 1.26**）
- npm `@wailsio/runtime@3.0.0`
- helper 的 `go.mod` 是 `go 1.26.0`，CI 用 `1.27.3`

---

## 2. 现状速览（需要迁移的部分）

| 路径 | 内容 | 迁移去向 |
| --- | --- | --- |
| `src/main/main.ts` | Electron 启动、窗口、托盘、对话框、通知、开机启动、safeStorage、电源事件 | Go：`desktop/main.go` 等（Wails 外壳） |
| `src/main/preload.ts` | `window.starrail = { command, subscribe }` | 前端改用 Wails runtime，见 §4 |
| `src/main/controller.ts` | 核心状态机 `ClientController`（334 行，写得很紧凑） | Go：`desktop/core/controller.go` |
| `src/main/demo.ts` | 演示面板 | Go |
| `src/domain/*` | 授权门禁、时钟/Budget、订阅解析、规则校验、严格 JSON、信任 URL、身份路径 | Go |
| `src/services/*` | HTTP、面板适配器、同步、端点池、策略/更新验签、下载、存储、提醒、规则资源、诊断 | Go |
| `src/platform/*` | helper RPC 客户端（Ed25519 握手）、Xray 探测、网络状态机、网卡变化监听 | Go |
| `src/shared/{schema,view,errors}.ts` | 类型 + zod 校验 + 错误文案 | **保留**给前端和构建工具用；Go 侧另写一份等价校验 |
| `src/renderer/*` | React UI | 保留，只改桥接 |

Electron 主进程只通过两个通道和界面交互：
- `starrail:intent`：invoke(Command) → `CommandResult { ok, state: AppView, error? }`
- `starrail:state`：主进程推送 `AppView`

`AppView`、`Command` 的结构见 `src/shared/view.ts` 和 `src/shared/schema.ts`，Go 侧 JSON 输出必须**逐字段一致**（数组不能是 `null`，可空字段输出 `null`）。

---

## 3. 建议的 Go 结构

```
desktop/                      # 新 Go 模块，例如 module work.starrail/client/desktop
  go.mod                      # go 1.26，依赖 wails/v3 v3.0.0
  main.go                     # application.New(...)，窗口/托盘/事件接线
  bridge.go                   # type Bridge struct；Command(json.RawMessage) 方法
  shell_dialogs.go            # 把回调式对话框包装成阻塞调用
  secret_{darwin,windows,linux}.go  # 系统钥匙串保存数据密钥
  core/                       # 一个包，对应原来的 domain + services + platform + controller
    errors.go json.go trust.go schema.go subscription.go compiler.go coreconfig.go
    authorization.go selection.go clock.go budget.go
    http.go panel.go sync.go endpoints.go policy.go update.go download.go
    storage.go reminders.go resources.go diagnostics.go
    network.go native.go probe.go netevents.go
    controller.go view.go demo.go
    *_test.go                 # 由 tests/*.test.ts 移植
```

`core` 放在一个包里，和 TS 的模块关系一致，也能避免循环引用。

### 3.1 并发模型（重要）

TS 是单线程 + async，代码默认「两个 await 之间是原子的」，大量逻辑依赖 generation 计数做「await 回来后检查是否已过期」。建议在 Go 里用**一把大锁**来模拟：

```go
type Loop struct{ mu sync.Mutex }
func (l *Loop) Await(fn func()) { l.mu.Unlock(); defer l.mu.Lock(); fn() } // 对应 await：IO 期间释放锁
func (l *Loop) Go(fn func())    { go func() { l.mu.Lock(); defer l.mu.Unlock(); fn() }() } // 对应 void promise
```

- 所有入口（UI 命令、1 秒 tick、网卡变化、helper 心跳失败、下载回调）进入时先加锁。
- 所有网络/磁盘/子进程/等待 future 的操作都包在 `Await` 里。
- TS 里的 Promise 队列（`SecureStore`/`JsonStore`/`PolicyService`/`ResourceCoordinator`/`ExpiryReminders`/`ArtifactDownload` 的串行化）各用一把独立的 `sync.Mutex`，**必须在 `Await` 内获取**，否则会死锁。
- `if (this.running) return this.running` 这类「共享同一个进行中的 Promise」，改成 `future{done chan struct{}; err error}`，等待时 `Await(func(){ <-f.done })`。
- `emit()` 改成非阻塞地往 `dirty` channel 发信号；由单独的 goroutine 加锁算 `view()`，再 `app.Event.Emit("starrail:state", view)`。这样可以合并推送，也避免重入死锁。`closing` 之后不再推送。
- `Budget` 对应 `context.WithTimeout`，带父 context；`Run(fn)` 在执行前先检查，`fn` 返回后如果 ctx 已取消，统一返回 `CANCELLED`（偏保守，和 TS 的 race 语义基本一致）。
- tick 用串行 ticker（上一个 tick 没跑完就不起下一个）。

---

## 4. 前端改动

`src/renderer/main.tsx` 只依赖 `ClientBridge`，所以只需要新增一个 Wails 实现：

```ts
import { Call, Events } from '@wailsio/runtime';
const wailsBridge: ClientBridge = {
  command: cmd => Call.ByName('main.Bridge.Command', cmd),
  subscribe: fn => Events.On('starrail:state', e => fn(e.data as AppView)), // 返回取消订阅函数
};
const bridge = isWails ? wailsBridge : previewBridge();
```

- 绑定方法名格式是 `<包路径>.<类型名>.<方法名>`；`package main` 里 `type Bridge` 的 `Command` 就是 `main.Bridge.Command`。用 `application.NewService(&Bridge{...})` 注册。
- `index.html` 的 CSP：`connect-src` 去掉 `ws://127.0.0.1:5173`（开发模式另行处理）。Wails 的 runtime 走同源请求 `/wails/runtime`，`'self'` 就够了。
- `previewBridge` 和 `npm run preview:ui`、`tools/ui-smoke.mjs` 保持不变。
- `Bridge.Command` 在 Go 里要做和 `CommandSchema` 等价的严格校验（未知字段拒绝、邮箱 ≤254、密码 1..1024、nodeIds 1..10 等），失败返回 `INVALID_INPUT`。

---

## 5. Electron API → Wails v3 对照

| Electron | Wails v3 |
| --- | --- |
| `BrowserWindow` | `app.Window.NewWithOptions(application.WebviewWindowOptions{Width:1180, Height:810, MinWidth:780, MinHeight:640, BackgroundColour…})` |
| 关闭时隐藏到托盘 | `window.RegisterHook(events.Common.WindowClosing, func(e){ e.Cancel(); … })`。**建议改成关闭时真正销毁窗口，点托盘再重建**：WebView 进程就能释放，这才是省内存的大头 |
| `Tray` + `Menu` | `app.SystemTray.New()`，`SetIcon`/`SetTemplateIcon`、`SetMenu`、`OnClick`。原来 Linux 不建托盘，保持一致 |
| `dialog.showMessageBox` | `app.Dialog.Question()/Info()`，`AddButton(...).OnClick(cb)`、`SetCancelButton`、`Show()` 都是**回调式**，需要用 channel 包成阻塞的 `ask(title, msg, detail, buttons) int` |
| `dialog.showSaveDialog` | `app.Dialog.SaveFileWithOptions(...)` |
| `dialog.showErrorBox`（启动失败） | `app.Dialog.Error()` |
| `Notification` | `github.com/wailsapp/wails/v3/pkg/services/notifications` |
| `shell.openExternal` | `app.Browser.OpenURL(url)`（URL 先过 `trustedUrl`） |
| `app.setLoginItemSettings` / Linux autostart `.desktop` | `app.Autostart.Enable()/Disable()`（Linux 是否写 `~/.config/autostart` 要确认；不行就沿用原来的 `.desktop` 写法） |
| `requestSingleInstanceLock` + `second-instance` | `Options.SingleInstance`（`UniqueID` 用 appId，`OnSecondInstanceLaunch` 里 show+focus） |
| `powerMonitor suspend/resume` | `app.Event.OnApplicationEvent(events.Common.SystemWillSleep / SystemDidWake, …)` |
| `before-quit` 先断网再退出 | `Options.ShouldQuit` 返回 false 并异步执行 `controller.Stop()`，完成后再 `app.Quit()`；失败时弹「网络恢复未确认」 |
| `window focus` → `renewal-return` | 窗口 focus 事件 `events.Common.WindowFocus` |
| `app.getPath('userData')` | 手动计算：macOS `~/Library/Application Support/<appId>`、Windows `%APPDATA%\<appId>`、Linux `$XDG_CONFIG_HOME/<appId>`（与 Electron 版路径相同，旧的 JSON 数据可以直接复用） |
| `process.getSystemVersion()` | macOS `sysctl kern.osproductversion`；Windows 用 `RtlGetVersion` 取 build（`osVersionAtLeast` 比较的是 `10.0.22000` 这类格式）；Linux 读 `/etc/os-release` |
| `safeStorage` | 见 §6 |
| `worker_threads` 解析订阅 | 普通 goroutine + 3 秒超时 + ctx 取消。如果要保留原来的内存上限，可以 fork 自身做子进程，但不是必须 |
| 渲染进程权限拦截（navigate、window.open、permission） | Wails 没有 Node 集成；仍应只加载内嵌资源、不打开外部导航 |

---

## 6. 安全存储（替代 safeStorage）

- 首次运行生成 32 字节随机数据密钥，存进系统钥匙串（service=`appId`，account=`session-key`）。会话 JSON 用 AES-256-GCM 加密写到 **`session.v2.enc`**。旧的 `session.enc` 是 Electron safeStorage 格式，没法解密，直接忽略或删除即可，用户需要重新登录一次（目前还是开发版本，可以接受）。
- 可选库：`github.com/zalando/go-keyring`（GitHub CLI 在用）。先确认它在 macOS 上不是通过命令行参数传密钥（避免密钥出现在 `ps` 里）；如果是，就改用 cgo 调 Security 框架，或者用 `keybase/go-keychain`。Windows 也可以直接用 DPAPI（`CryptProtectData`）。
- 状态语义保持不变：钥匙串不可用 → `memory`（只放内存，不落盘明文）；有密文但解不开 → `locked`，并报 `STORAGE_LOCKED`。Linux 对应原来的 `basic_text`/`unknown` 后端：没有 Secret Service 时就是 `memory`。

---

## 7. 必须逐字节兼容的地方（容易踩坑）

1. **节点 ID / connectionFingerprint**：`sha256(JSON.stringify(connection))`。偏好里保存的 `nodeId`，以及策略里的 `nodeOperations[].nodeId` 都依赖它，**ID 变了，已保存的选择和运营策略都会失效**。Go 侧必须按 JS 对象**插入顺序**手动拼 JSON：
   - 公共前缀：`protocol, host, port, credential, transport, security, tcp, udp, ipv6`
   - vmess 追加：`method, sni, wsHost, wsPath, fingerprint`
   - ss 追加：`method`
   - vless/trojan 追加：`sni, flow, [fingerprint（URL 里有 fp 时）], [publicKey, shortId（reality）], [fingerprint（前面没设置时取默认值 hellochrome_120）]`
   - 值为 `undefined` 的键不输出；空字符串 `''` 要输出（比如 `flow:""`）
   - 不认识的协议（hysteria2 等）：`id = sha256(JSON.stringify(line))`，也就是带引号的 JSON 字符串
   - 字符串转义按 JS 规则：只转义 `"`、`\` 和 `<0x20` 的控制字符（`\b \f \n \r \t`，其余用小写 `\u00xx`），**不要**转义 `< > &`、U+2028、U+2029。不要直接用 `encoding/json`，自己写 `jsString()`
   - 用 TS 版跑一遍 `tests/fixtures.ts` 的 `uri`，记下 ID 作为 Go 测试的期望值
2. **提醒去重 key**：`sha256(JSON.stringify([tenant, accountId, expiryMs]))`，例如 `["t","id",1735689600000]`。
3. **严格 JSON**（`src/domain/json.ts`）：拒绝重复键（包括转义后相同的键，例如 `"a"` 和 `"a"`）、`__proto__`/`prototype`/`constructor`、嵌套深度 >32、不安全整数（>2^53-1）、尾随垃圾，并且有大小上限。
4. **zod `.strict()` 等价**：拒绝未知字段，必填字段必须存在；`.nullable()` 必须存在但可以是 null；`.optional()` 可以缺省但不能是 null；`.default()` 可以缺省。建议写一个基于反射的 `decodeStrict`：先跑严格 JSON 扫描，再按 struct tag（`omitempty` 表示可缺省，自定义 `nullable` 选项表示可为 null）检查键，最后对每个类型调用 `Validate()` 检查正则、范围、枚举和 `superRefine` 规则。
5. **`normalizeAccount` 的 JS 语义**：`rawBanned === 1 || === true`、`String(id)`、`===` 严格相等、`{...subscription, ...info}` 合并，流量字节数用 `math/big`（最多 30 位十进制）。JSON 数字要用 `UseNumber` 解析，才能区分整数。
6. 时间统一用毫秒 `int64`；`Date.parse` 对应 RFC3339 解析；`usableUntil` 取 min 时，`Infinity` 用 `math.MaxInt64` 表示。
7. `ConservativeClock`：单调时钟用 `time.Since(anchor)`（Go 的 monotonic reading），回拨阈值 120 秒，逻辑原样移植。

---

## 8. helper（`native/helper`）需要的改动

- 去掉 `app.asar`：`main.go` 的 `installApplication` 不再计算 `archive`/`archiveHash`；从 `types.go` 的 `Installation` 删掉 `AppArchive`/`ArchiveSHA256`；`common.go` 的 `verifyPeer` 只校验可执行文件的路径、哈希和 stat 缓存。可执行文件内嵌了前端资源，校验它就等于覆盖了 UI。
- `verifyPeer` 里 Electron 专用的参数黑名单（`--type=`、`electron_run_as_node` 等）可以保留，因为后面还有 `validAppArguments` 白名单（`--hidden/--autostart/--updated/-psn_`）兜底。
- 资源目录布局保持：macOS 是 `<App>.app/Contents/Resources/native/<target>/`，Windows/Linux 是 `<安装目录>/resources/native/<target>/`，所以 `applicationResources()` 不用改。
- 可执行文件名由 `tools/build-native.py` 写进 `build.json`：Windows `<产品名>.exe`，macOS `<产品名>`，Linux `<productId>`。新打包脚本必须产出完全相同的名字和路径。
- `probe-core`（`probe_worker.go`）校验父进程就是 App 可执行文件，Go 版 App 用同样方式启动它即可：`helper probe-core <pid> [--check]`，配置从 stdin 传入。
- 改完跑 `cd native/helper && go test -race ./...`，`GOOS=windows go vet ./...` 也要通过。

---

## 9. 打包（替换 electron-builder）

已实现 `tools/package.py`，替换 `electron-builder.cjs` 和 `tools/package-windows.cjs`。共同步骤：
1. `vite build` → `desktop/frontend/dist`（用 `//go:embed` 嵌进二进制）
2. `go build -tags production -trimpath -ldflags "-s -w"`（Linux 加 `gtk3`）；Windows 再加 `-H windowsgui`
3. 复制 `resources/native/<target>`、`resources/rules`、`resources/licenses`、`core-lock.json`、`THIRD_PARTY_NOTICES.md`、`tools/import-rules.py`（作为 `rules/import-rules.py`）
4. 保留原 `checkHelperConfiguration()`：校验 `native/helper/build.json` 和当前品牌配置一致；production 构建前运行 `release-check.ts`
5. 保留 afterPack 里的核心/helper 哈希校验

各平台：
- **macOS**：手工拼 `.app`（`Contents/MacOS/<产品名>`、`Info.plist`（CFBundleIdentifier=appId，LSMinimumSystemVersion=14.0，版本号）、`Resources/icon.icns`（用 `sips` + `iconutil` 从 `resources/icon.png` 生成））。没有证书时执行 `codesign --force --sign - <App>.app`，**不要加 `--deep`**，否则会改掉 xray/helper 的字节，导致哈希固定失效。dmg 用 `hdiutil create`，zip 用 `ditto -c -k --keepParent`（应用内更新用 zip）。
- **Windows**：自己写 NSIS 脚本（`makensis`，Linux 上也能跑，`apt install nsis`）。要求：perMachine，安装到 `$PROGRAMFILES64\<产品名>`，支持 `/S` 和 `/D=`（`update_windows.go` 用这两个参数静默安装）；安装后运行 `resources\native\win32-x64\helper.exe install --app "$INSTDIR"`，失败就中止；卸载时运行 `$PROGRAMFILES64\<productId>-service\helper.exe uninstall`，失败就 Abort。覆盖安装不走卸载，所以不需要 `${isUpdated}`。图标和版本信息用 `go-winres` 或 `rsrc` 生成 `.syso`。Windows 11 和保持更新的 Windows 10 自带 WebView2；安装器检测不到运行库时提示打开微软下载页。最低 Windows 10 1809（build 17763），与 `tools/release-assets.mjs` 的 `minimumOS` 一致。
- **Linux**：`dpkg-deb --build --root-owner-group`。包名和可执行文件名都是 `productId`，安装到 `/opt/<产品名>/`（`update_linux.go` 的 `dpkg-repack` 依赖这个包名）。依赖：`libgtk-3-0t64, libwebkit2gtk-4.1-0, iproute2, nftables, systemd-resolved, polkitd, pkexec, dpkg-repack`，去掉 `libnss3/libasound2t64/libgbm1` 这些 Chromium 依赖。postinst 保留 `update-alternatives` 和 `helper install --app`，去掉 `chrome-sandbox` 和 apparmor 相关内容；prerm 沿用 `packaging/linux/before-remove.sh`。构建机要装 `libgtk-3-dev libwebkit2gtk-4.1-dev`。
- `tools/release-assets.mjs`：`unpacked` 目录名按新脚本的输出调整，产物命名规则不变。
- `tools/verify-package.py`：去掉 `app.asar`、`LICENSE.electron.txt`、`LICENSES.chromium.html` 这几项检查。

---

## 10. 构建脚本、测试与 CI

- `package.json`：删除 `electron`、`electron-builder`、`@electron/fuses`、`esbuild`（如果没有其他地方再用）；新增 `@wailsio/runtime@3.0.0`。`main` 字段删掉。
- `tools/build.ts`：不再用 esbuild 打包主进程。改为 vite 构建，并把 `build-config.json`、`adapter-contract.json`、`native-manifest.json`、`rules/baseline.json`、`icon.png` 放到 Go 能 `embed` 的位置（或者放进 resources 目录，运行时读取。原来是从 `dist/` 读取的）。
- `tools/develop.ts`：改为启动 vite dev server，再 `go run` 桌面程序，并通过环境变量让窗口加载 `http://127.0.0.1:5173`（只在非 production 构建时允许，对应原来的 `STARRAIL_DEV_UI`）。`--demo` 参数保留。
- 保留的 TS：`src/shared/*`、`src/domain/{trust,json,identity,compiler}.ts`、`src/services/{policy,update,resources,panel(ContractSchema)}.ts`，原因是 `tools/brand.ts`、`build.ts`、`config-check.ts`、`release-check.ts`、`export-schemas.ts` 和 `tests/server.test.ts`、`tests/brand.test.ts` 还在用。其余主进程专用的 TS 模块和对应测试移植完再删。
- 测试移植成 Go：`authorization, subscription, policy, core-config(只保留 compileProbe 部分), sync, storage-panel, download, resource-coordinator, lifecycle, network, update-selection, controller-lifecycle, controller-probe, manual-update`。`tests/fixtures.ts` 里的固定时间、密钥生成和 `envelope()` 签名函数在 Go 里各写一份。
- `compileTun`（`src/domain/core-config.ts`）运行时没用到，helper 自己会编译 TUN 配置，所以只在 core-smoke 里用。可以不移植，或者把 core-smoke 的 TUN 检查改成测 helper 的 `compiler.go`。
- `tools/core-smoke.ts`、`download-smoke.ts` → 写成需要环境变量才运行的 Go 测试（`STARRAIL_CORE_SMOKE=1`）。
- `tools/electron-smoke.mjs`、`packaged-smoke.mjs` 是 Playwright 驱动 Electron 的，直接删除。打包后的检查改为校验产物内容和哈希，加上手动启动一次 `--demo`。
- CI：
  - `check.yml`：增加 `desktop/` 的 `gofmt`、`go vet`、`go test -race`；Linux job 先 `apt-get install libgtk-3-dev libwebkit2gtk-4.1-dev`
  - `package-development.yml`：把 `npx electron-builder ...` 换成新打包脚本；Windows runner 需要 `makensis`（`choco install nsis`，如果镜像里没有）；setup-go 的 `cache-dependency-path` 加上 `desktop/go.sum`
  - `release.yml` 基本不变
- 文档：README（「Electron + TypeScript」→「Wails + Go + React」，开发命令）、`docs/architecture.md`（Renderer/Preload/主进程 → WebView/Bridge/Go 协调器，ASAR 哈希 → 可执行文件哈希）、`docs/native-service.md`、`THIRD_PARTY_NOTICES.md`（去掉 Electron/Chromium，加上 Wails MIT 许可）。

---

## 11. 推荐执行顺序和验收标准

1. **core 包移植 + Go 测试**：先移植纯逻辑（errors/json/trust/schema/subscription/compiler/authorization/clock/selection/policy/update/endpoints），再移植 IO 部分（http/panel/sync/storage/download/resources/reminders/diagnostics/network/native/probe/netevents），最后移植 controller。
   验收：`go test -race ./...` 通过；节点 ID 和 TS 版完全一致；`strictJson` 的拒绝用例全部覆盖。
2. **Wails 外壳**：窗口、托盘、对话框、通知、开机启动、单实例、睡眠/唤醒、退出前断网、钥匙串存储。
   验收：`go run . --demo` 能看到示例账号，点击连接时提示「网络组件不可用」，不会出现「已连接」；`AppView` JSON 里不含 token 或节点凭据（原 `electron-smoke` 断言的内容）。
3. **前端桥接**：验收：真实窗口和 `npm run test:ui`（预览模式）都能用。
4. **helper 去掉 asar**：验收：helper 测试通过；`helper install --app <新 App 路径>` 能写出不含 archive 的 `installation.json`。
5. **打包 + CI**：四个目标都能产出 dmg/zip、exe、deb；`verify-package.py` 通过；ad-hoc 签名的 mac 包可以启动。
6. 实际测量空闲内存和包体积，和 Electron 版对比后写进 README。

---

## 12. 原 Electron 实现的性能背景

旧 Electron 版本关闭窗口只是 `window.hide()`（`src/main/main.ts:98`），渲染进程一直驻留在内存里；`controller.ts:146` 每秒 tick 一次，窗口隐藏时也在推送状态。改成关闭时 `window.destroy()`、点托盘再 `createWindow()`，并且没有窗口时不推送状态，托盘常驻时的内存和 CPU 就能明显下降。Wails 版也应该照这样做（见 §5）。
