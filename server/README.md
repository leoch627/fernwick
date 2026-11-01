# 自建端点

一个 Go 程序，给客户端提供：

- `/v1/release`、`/v1/policy`：签名的更新索引和运营策略（含远程规则）
- `/files/...`：安装包、更新包、规则文件，支持断点续传
- `/`：下载页，自动推荐访客的系统，附「第一次打开被系统拦截」的处理说明
- `/v1/telemetry`、`/v1/report`：客户端遥测和问题报告
- `/admin/`：排查页面，输入用户邮箱看最近的连接记录，输入 6 位问题编号看诊断报告

数据全部在一个目录里（默认 `/var/lib/v2board-endpoint`）：签名状态、上传的文件、按天保存的遥测（默认留 30 天）、问题报告（默认留 90 天）。没有数据库。

## 选机器和域名

用户在大陆，所以机器要选到大陆线路好的：香港 CN2 GIA / CMI、日本软银这类。不要放在大陆云厂商的对象存储上：放翻墙客户端安装包会被封号。

准备一个主域名，再准备一两个备用域名指向同一台机器。主域名写进 systemd 里的 `PUBLIC_ORIGIN`，所有域名写进 Caddyfile，并按顺序填进 GitHub 变量 `UPDATE_ENDPOINT`（空格分隔）。客户端按顺序尝试，主域名被墙时用备用域名，下载的文件仍按哈希校验。

## 部署

以 Ubuntu 为例。

1. 编译：Actions → Update endpoint → `build`，下载产物；或本地：
   ```sh
   cd server && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o v2board-endpoint .
   ```
2. 上传并安装（签名私钥就是 GitHub Secret `SIGNING_KEY` 那一份）：
   ```sh
   sudo install -m 755 v2board-endpoint /usr/local/bin/
   sudo install -d -m 700 /etc/v2board-endpoint
   sudo install -m 600 private.pem /etc/v2board-endpoint/signing.pem
   sudo cp deploy/v2board-endpoint.service /etc/systemd/system/
   sudo nano /etc/systemd/system/v2board-endpoint.service   # 改 PUBLIC_ORIGIN
   sudo systemctl daemon-reload && sudo systemctl enable --now v2board-endpoint
   ```
3. HTTPS：安装 Caddy，把 `deploy/Caddyfile` 里的域名改成你的，放到 `/etc/caddy/Caddyfile`，`sudo systemctl reload caddy`。Caddy 会自己申请和续期证书。也可以用 nginx，记得把 `client_max_body_size` 调到 2G 并传 `X-Real-IP`。
4. 检查：`curl https://你的域名/healthz` 返回 `ok`。打开 `https://你的域名/` 是下载页（发布第一个版本前显示「暂无可下载的版本」）。
5. 发布第一个版本：打 tag 触发 Release 工作流，它会上传安装包并登记版本。

升级端点程序只需替换 `/usr/local/bin/v2board-endpoint` 后 `sudo systemctl restart v2board-endpoint`，数据目录不动。

## 排查用户问题

打开 `https://你的域名/admin/`，管理令牌用下面任一方式得到：

```sh
node tools/admin-token.mjs ~/keys/signing/private.pem
v2board-endpoint -key-file /etc/v2board-endpoint/signing.pem -print-admin-token
```

- 输入用户邮箱：看最近几天的事件。`connect` 是每次连接（`stage` 是卡住的步骤，`code` 是错误码，`tcp/dns/udp/ipv6` 是连上后的检测结果），`api` 是面板域名的可达性（`ok=false` 的那个域名大概率被墙了），`login`、`sync`、`dropped`（连着连着断了）。
- 输入问题编号：看用户点「上报问题」时的完整诊断。网络自检里，`dns` 和 `doh` 的地址不一样说明 DNS 被污染；`tcp=reset` 或 `tls=reset` 是被阻断；`timeout` 是线路不通；`node` 类的检查看节点服务器本身能不能连。

遥测不包含用户访问的网站、DNS 查询、流量、密码、订阅链接和节点密码。

## 命令行参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-listen` | `127.0.0.1:8787` | 监听地址，前面放 Caddy / nginx |
| `-data` | `/var/lib/v2board-endpoint` | 数据目录 |
| `-origin` | 环境变量 `PUBLIC_ORIGIN` | 主域名，写进签名的下载地址 |
| `-key-file` | 环境变量 `SIGNING_KEY_FILE` | 签名私钥，也可以用环境变量 `SIGNING_KEY` 直接给内容 |
| `-trust-proxy` | `true` | 从 `X-Real-IP` / `X-Forwarded-For` 取用户 IP |
| `-telemetry-days` / `-report-days` | 30 / 90 | 保留天数 |

## 测试

```sh
cd server && go test ./...
```

测试用客户端自己的验签代码（`desktop/core`）检查发布的索引、策略和规则，客户端不认的输出在这里就会失败。
