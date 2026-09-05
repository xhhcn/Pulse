<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="Pulse Logo">
</p>

<h1 align="center">Pulse</h1>

<p align="center">
  <b>轻量级服务器监控系统</b><br>
  实时监控 CPU、内存、磁盘、网络等指标
</p>

<p align="center">
  <a href="README_EN.md">English</a> | <a href="README.md">中文</a>
</p>

<p align="center">
  <a href="https://github.com/xhhcn/Pulse/releases/tag/v1.3.18"><img src="https://img.shields.io/badge/release-v1.3.18-blue?style=flat-square" alt="Release"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/pulls/xhh1128/pulse?style=flat-square&color=blue" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/image-size/xhh1128/pulse/latest?style=flat-square&color=blue" alt="Docker Size"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Astro-4.0+-FF5D01?style=flat-square&logo=astro&logoColor=white" alt="Astro">
  <img src="https://img.shields.io/badge/Platform-amd64%20%7C%20arm64-lightgrey?style=flat-square" alt="Platform">
</p>

---

<p align="center">
  由 <a href="https://www.dooki.cloud" target="_blank"><b>DokiDoki CDN</b></a> 赞助<br><br>
  <a href="https://www.dooki.cloud" target="_blank">
    <img src="assets/doki.png" height="60" alt="DokiDoki CDN">
  </a>
</p>

---

## ✨ v1.3.0 新功能

- 🔐 **共享密钥认证** - 所有客户端使用统一的共享密钥连接服务器，简化部署配置
- 🏷️ **特殊标签支持** - 新增 `traffic:in/out` 和 `speed:in/out` 标签，实时显示流量统计和网络速率
- 🎨 **自定义 CSS/JS** - 支持全站自定义样式和脚本，打造个性化监控面板

---

## 🚀 服务端安装

### 方式一：独立二进制部署（推荐新手和 VPS 用户）

#### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash
```

脚本会自动：
- ✅ 检测系统架构（amd64 / arm64）
- ✅ 下载对应的二进制到 `/opt/pulse/pulse-server`
- ✅ 配置 `pulse-server.service` 并设置开机自启
- ✅ 顺手装上迁移辅助脚本 `/opt/pulse/scripts/{backup,restore,migrate}.sh`，并创建 `pulse-backup` / `pulse-restore` / `pulse-migrate` 三个 CLI 短链（详见 [迁移到另一台服务器](#-迁移到另一台服务器)）

#### 更新服务端

**amd64:**
```bash
sudo systemctl stop pulse-server && sudo wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-amd64 -O /opt/pulse/pulse-server && sudo chmod +x /opt/pulse/pulse-server && sudo systemctl start pulse-server
```

**arm64:**
```bash
sudo systemctl stop pulse-server && sudo wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-arm64 -O /opt/pulse/pulse-server && sudo chmod +x /opt/pulse/pulse-server && sudo systemctl start pulse-server
```

#### 卸载服务端

> 一键安装脚本除了主程序还会落地三件东西：迁移辅助脚本 `/opt/pulse/scripts/{backup,restore,migrate}.sh`、`/usr/local/bin/pulse-{backup,restore,migrate}` 三个 CLI 短链，以及 `/opt/pulse/data/`（数据库 `metrics.db` 在这里）。卸载时按需选择以下两种之一：

**仅删除程序（保留 `/opt/pulse/data/` 下的数据库，方便回滚或日后重装）:**
```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && \
sudo rm -f /usr/local/bin/pulse-migrate /usr/local/bin/pulse-backup /usr/local/bin/pulse-restore && \
sudo rm -f /opt/pulse/pulse-server /etc/systemd/system/pulse-server.service && \
sudo rm -rf /opt/pulse/scripts && \
sudo systemctl daemon-reload
```

**完全删除（包括数据库 `metrics.db`，不可逆）:**
```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && \
sudo rm -f /usr/local/bin/pulse-migrate /usr/local/bin/pulse-backup /usr/local/bin/pulse-restore && \
sudo rm -f /etc/systemd/system/pulse-server.service && \
sudo rm -rf /opt/pulse && \
sudo systemctl daemon-reload
```

#### 手动安装

**Linux (amd64)**
```bash
# 下载
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-amd64
chmod +x pulse-server-standalone-linux-amd64

# 运行
./pulse-server-standalone-linux-amd64
```

**Linux (arm64)**
```bash
# 下载
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-arm64
chmod +x pulse-server-standalone-linux-arm64

# 运行
./pulse-server-standalone-linux-arm64
```

访问 `http://YOUR_IP:8008` 查看监控面板

---

### 方式二：Docker 部署（推荐生产环境）

[![Docker](https://img.shields.io/badge/Docker-xhh1128/pulse-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/xhh1128/pulse)

#### Docker Compose

```bash
mkdir pulse && cd pulse
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml
docker compose up -d
```

> **IPv6 支持**：如果您的服务器需要 IPv6 支持，请参考下方的 [Docker IPv6 配置](#docker-ipv6-配置) 章节。

#### Docker Run

```bash
docker run -d \
  --name pulse-monitor \
  -p 8008:8008 \
  -v $(pwd)/pulse-data:/app/data \
  --restart unless-stopped \
  xhh1128/pulse:latest
```

访问 `http://YOUR_IP:8008` 查看监控面板

---

## 🌐 Docker IPv6 配置

Pulse 支持 IPv4/IPv6 双栈，如果您的服务器需要 IPv6 支持，请按照以下步骤配置：

### 前置要求

1. **确保宿主机已启用 IPv6**
   ```bash
   # 检查 IPv6 是否启用
   ip -6 addr show
   
   # 检查 IPv6 转发是否启用
   sysctl net.ipv6.conf.all.forwarding
   # 如果输出为 0，需要启用：
   sudo sysctl -w net.ipv6.conf.all.forwarding=1
   
   # 永久启用（编辑 /etc/sysctl.conf）
   echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
   ```

2. **配置 Docker Daemon 启用 IPv6**

   编辑或创建 `/etc/docker/daemon.json`：
   ```json
   {
     "ipv6": true,
     "fixed-cidr-v6": "fd00:dead:beef:c0::/80",
     "experimental": true,
     "ip6tables": true
   }
   ```
   
   > **说明**：
   > - `ipv6: true` - 全局启用 Docker 的 IPv6 支持（**必需**）
   > - `fixed-cidr-v6` - Docker 使用的 IPv6 子网范围（可根据实际情况调整）
   > - `experimental: true` - 启用实验性功能（某些 IPv6 功能需要）
   > - `ip6tables: true` - 启用 IPv6 的 iptables 支持（用于网络隔离和端口映射）
   
   重启 Docker 服务使配置生效：
   ```bash
   sudo systemctl restart docker
   ```

3. **配置 docker-compose.yaml 启用 IPv6**

   在 `docker-compose.yaml` 中配置网络启用 IPv6：
   ```yaml
   services:
     pulse:
       image: xhh1128/pulse:latest
       container_name: pulse-monitor
       ports:
         - 8008:8008
       volumes:
         - pulse-data:/app/data
       restart: unless-stopped
       networks:
         - pulse-network

   volumes:
     pulse-data:

   networks:
     pulse-network:
       enable_ipv6: true
       ipam:
         driver: default
   ```

4. **重新创建容器**

   ```bash
   docker compose down
   docker compose up -d
   ```

5. **验证 IPv6 配置**

   ```bash
   # 检查容器 IPv6 地址
   docker exec pulse-monitor ip -6 addr show
   
   # 测试 IPv6 连接（如果容器有 ping6）
   docker exec pulse-monitor ping6 -c 2 2001:4860:4860::8888
   ```

---

## 📦 客户端安装

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

### macOS（Intel / Apple Silicon）

安装脚本会自动检测 CPU 架构，并将服务注册为 `launchd` 守护进程（开机自动启动）：

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

> **注意**：macOS 需要 `sudo` 权限以便将 `.plist` 写入 `/Library/LaunchDaemons/`。

**macOS 服务管理命令：**

```bash
# 查看运行状态
sudo launchctl print system/com.pulse.client

# 查看日志
tail -f /var/log/pulse-client.log

# 重启服务（推荐方式）
sudo launchctl kickstart -k system/com.pulse.client

# 停止服务
sudo launchctl bootout system/com.pulse.client

# 重新启动已停止的服务
sudo launchctl bootstrap system /Library/LaunchDaemons/com.pulse.client.plist
```

### Windows (管理员 PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "& { $env:AgentId='<ID>'; $env:ServerBase='<SERVER_URL>'; $env:Secret='<SECRET>'; irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex }"
```

| 参数 | 说明 |
|------|------|
| `<ID>` | 服务器唯一标识（在管理后台添加系统时设置） |
| `<SERVER_URL>` | 服务端地址，如 `http://your-server:8008` |
| `<SECRET>` | 认证密钥（在管理后台添加系统后自动生成，可在系统详情中查看） |

> **注意**：`--secret` 参数是可选的。如果服务端系统配置了 secret，则必须提供正确的 secret 才能成功注册。

### 卸载客户端

> 客户端默认开启自动更新，因此 systemd 上除了 `pulse-client.service` 还有 `pulse-client-update.service` + `pulse-client-update.timer` 两件，macOS 上则多一个 `com.pulse.client.update` 守护进程。下面的命令同时清理这些组件，无论之前是否启用过自动更新都能安全运行（缺失的 unit 会被忽略）。

**Linux (systemd):**
```bash
sudo systemctl stop pulse-client pulse-client-update.timer 2>/dev/null
sudo systemctl disable pulse-client pulse-client-update.timer 2>/dev/null
sudo rm -f /opt/pulse/probe-client /opt/pulse/update.sh \
  /etc/systemd/system/pulse-client.service \
  /etc/systemd/system/pulse-client-update.service \
  /etc/systemd/system/pulse-client-update.timer
sudo systemctl daemon-reload
```
> 同一台机器若同时跑了服务端，请保留 `/opt/pulse/`（仅删上面列出的客户端相关文件即可），数据库不受影响。

**macOS（含自动更新）:**
```bash
sudo launchctl bootout system/com.pulse.client 2>/dev/null || true
sudo launchctl bootout system/com.pulse.client.update 2>/dev/null || true
sudo rm -rf /opt/pulse \
  /Library/LaunchDaemons/com.pulse.client.plist \
  /Library/LaunchDaemons/com.pulse.client.update.plist
```

**Windows (管理员 PowerShell):**
```powershell
Stop-ScheduledTask -TaskName 'PulseClient' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'PulseClient' -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetFirewallRule -DisplayName 'Pulse Monitoring Client*' -ErrorAction SilentlyContinue; Remove-Item -Path "$env:ProgramFiles\Pulse" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## ⚙️ 使用方法

1. 访问 `http://YOUR_IP:8008/admin` 进入管理后台
2. 首次访问设置管理密码
3. 点击 **Add System** 添加服务器
4. 添加系统后，系统会自动生成一个 **Secret**（认证密钥）
5. 在目标机器上运行客户端安装命令，**必须包含正确的 Secret**
6. 数据自动上报，实时显示

> **提示**：在管理后台的系统列表中，点击系统右侧的复制按钮可以快速复制包含 Secret 的安装命令。

---

## 📊 监控指标

| 指标 | 内容 |
|------|------|
| **CPU** | 使用率、核心数、型号 |
| **内存** | 使用率、总量 |
| **磁盘** | 使用率、总量 |
| **网络** | 上传/下载速率、TCPing延迟 |
| **系统** | 运行时间、IP、位置 |

---

## 🎨 二次开发 / 自定义主题

Pulse 的前端是独立的 Astro 项目，**完全和后端解耦**。如果你想 fork 出一个自己的主题（换皮、加组件、改交互），只需要动 `server/web/` 下面的代码，Go 后端不需要改一行。

### 主题代码在哪里

```
server/web/
├── src/
│   ├── pages/                    # 三个入口路由
│   │   ├── index.astro           #   /        公开仪表盘
│   │   ├── admin.astro           #   /admin   管理面板
│   │   └── login.astro           #   /login   登录页
│   ├── components/               # 9 个可复用组件，全部 Astro + Tailwind
│   │   ├── SystemTable.astro     #     主表 + TCPing 折线图
│   │   ├── AdminDashboard.astro  #     管理面板表格 + 模态框
│   │   ├── NavBar.astro / Footer.astro / LoadingState.astro
│   │   ├── LoginForm.astro / Icon.astro
│   │   └── SystemTableHeader.astro / SystemTableHeaderRow.astro
│   ├── styles/global.css         # 全局动画 + 自定义 Tailwind 工具
│   └── utils/i18n.ts             # 中英文词条（48 条）；新增语言只需扩展 Language 类型
├── tailwind.config.mjs           # 颜色调色板 + dark mode
└── astro.config.mjs              # Astro / Vite 配置（含 dev 代理，下面会讲）
```

### 本地开发工作流

```bash
git clone https://github.com/<你的用户名>/Pulse.git
cd Pulse/server

# 终端 1：跑后端（监听 :8080）
go run .

# 终端 2：跑前端（监听 :4321，自动热重载）
cd web
npm install
npm run dev
```

打开 `http://localhost:4321` 即可看到带热重载的页面。`astro.config.mjs` 已经把 `/api/*` 与 `/healthz` 代理到 `:8080`，**不用改任何 fetch 代码**。如果想对接远程后端（例如自己 VPS 上的实例）：

```bash
PULSE_API_BASE=https://your-pulse-instance.example.com npm run dev
```

### 出包 & 部署

两种路径都已经过端到端验证。任选其一：

**A. 独立二进制（先打前端，再编 Go）：**

```bash
# 1) 前端打包（产出 server/web/dist/）
cd server/web && npm run build

# 2) Go 编译，前端通过 embed.FS 嵌进去；交叉编译只需要换 GOOS/GOARCH
cd ..    # 回到 server/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o pulse-server .

# 3) 直接跑（数据库写到 ./data/metrics.db）
./pulse-server
```

> 前端必须先 `npm run build`：`go:embed all:web/dist` 是**编译期**指令，build 时没有 `dist/` 目录就会报错。

**B. Docker 镜像（一条命令搞定，前端打包发生在镜像内）：**

```bash
docker build -t my-pulse:dev .
docker run --rm -p 8008:8008 -v "$(pwd)/data:/app/data" my-pulse:dev
```

`Dockerfile` 多阶段构建会替你跑 `npm ci && npm run build`，再把 dist/ 喂给 nginx，Go 后端只走 API。本地改完主题，直接 `docker build` 一遍就好，不需要先单独 `npm run build`。

### 不需要碰的部分

* `server/main.go` & `server/store.go`：后端 API、鉴权、bbolt 存储，已经过几轮安全/性能审计，对主题开发完全透明。
* `client/`：跑在被监控机器上的 Go agent 代码。
* `scripts/`、`install-pulse-server.sh`、`docker/`：部署 / 运维相关。

### 上游协作

只是换皮的话保留独立 fork 就好。如果你做出来的功能有普适价值（一个新组件、一个新过滤器、一个 bug 修复），欢迎提 PR 回主仓库。

---

## 🚚 迁移到另一台服务器

Pulse 服务端的全部状态（系统列表、共享密钥、TCPing 历史、管理员密码、面板配置……）都只保存在 **一个 bbolt 文件** 里。仓库提供的 `scripts/migrate.sh` 把整个流程打包成 **一条命令**：在新服务器上跑一次，就能从旧服务器把所有数据搬过来，**旧服务器全程不停机、零数据丢失**。

> 客户端 `AGENT_ID` / `SECRET` 保持不变，只有 `SERVER_BASE`（服务端地址）可能需要改。  
> 如果旧端用的是域名 + 反代，只需把 DNS 切到新 IP 即可，客户端完全不用动。

### ✨ 一条命令完成迁移

```bash
# ── 在新服务器上 ──

# 1) 安装 Pulse（二选一）
#    A. 独立二进制（systemd） — 推荐，资源占用最小
#       安装器会顺便把 backup/restore/migrate 脚本装到 /opt/pulse/scripts/
#       并创建 pulse-migrate / pulse-backup / pulse-restore 三个命令。
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash

#    B. Docker Compose
# mkdir pulse && cd pulse && \
# curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml && \
# docker compose up -d && \
# curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/scripts/migrate.sh -o migrate.sh && chmod +x migrate.sh
#       migrate.sh 会自动从仓库拉取它所依赖的 backup.sh / restore.sh，一个文件够用

# 2) 一条命令迁移 —— 交互式输入旧服务器的管理员密码
sudo pulse-migrate --from https://OLD_HOST                 # 二进制方式（最便捷）
# 或在 Docker 目录里：
# sudo ./migrate.sh --from https://OLD_HOST

# 非交互（CI/自动化，推荐用 env var 避免密码进 `ps`）：
# sudo PASSWORD='旧服务器密码' pulse-migrate --from https://OLD_HOST -y
```

`migrate.sh` 按顺序完成：

1. 用你提供的密码登录 **旧服务器**，换取一次性管理员令牌（密码通过 stdin 传给 `curl`，不会出现在 `ps` 里）。
2. 调用 `GET /api/admin/backup` 拉一份 **事务级一致性** 的热备份——基于 bbolt 的 `Tx.WriteTo`，不会捕获到半写入页，**旧服务器不停机**。
3. 校验下载文件：大小 + bbolt 魔数 `0xEDDA0CED`，避免 `scp` 断流或误传成 `.gz` 直接使用。
4. 自动识别新服务器是 **Docker** 还是 **独立二进制**，停服 → 把当前 `metrics.db` 另存为 `metrics.db.pre-restore-<时间戳>`（一条命令回滚）→ 放入新文件 → 重启服务。
5. 轮询 `/healthz` 直到返回 200，或 60 秒超时后打印日志并给出回滚命令。

默认把下载的备份文件放在权限 `0700` 的私有临时目录，文件本身 `0600`，成功后自动清理；加 `--keep-backup ./pulse-backup.db` 可以保留一份做离线归档。

### 💾 只想手动备份？管理面板一键下载

进 `/admin` 登录后，表头右上角多了一个 **下载备份** 按钮（下载图标，绿色悬停色）。点一下浏览器就会保存一个 `pulse-backup-<UTC 时间戳>.db` —— 跟 `pulse-backup` / `migrate.sh` 拉到的**完全是同一个文件**（事务级一致热快照，基于 `Tx.WriteTo`），可以直接喂给 `sudo pulse-restore <文件>` 在任意新机器上还原。适合：没 SSH 环境、想快速做一次性备份、或者给迁移留个保险。

### 🔐 安全要点（认真看一眼，30 秒）

- **用 HTTPS 或 SSH 隧道**。备份里带着管理员密码哈希 + 每台机器的共享密钥，纯 HTTP 走公网等于把钥匙挂外面。脚本会在检测到非本地 `http://` 时弹出提醒。没有 HTTPS 时推荐：
  ```bash
  ssh -fN -L 8008:localhost:8008 user@OLD_HOST
  sudo pulse-migrate --from http://localhost:8008
  ```
- **别用 `--password '明文'`**。命令行参数在 `ps` 里所有本机用户都看得到。优先：交互式提示（无参数）或环境变量 `PASSWORD='...' pulse-migrate ...`。
- **备份文件 = 生产 DB**。保存时用 `0600` 权限（脚本已做），传输时走加密通道，不用了就删。
- **服务端已经做了多层防护**：登录 5 次失败锁 IP 15 分钟、密码 bcrypt、`/api/admin/backup` 只认 `Authorization: Bearer`（拒绝 `?token=` query，避免令牌进 nginx 日志）、每次备份都会写一条审计日志（包含客户端 IP）。

### 🔁 客户端地址更新（仅当 URL 变了）

```bash
# Linux（systemd 客户端）
sudo sed -i 's#http://OLD_HOST:8008#http://NEW_HOST:8008#g' \
  /etc/systemd/system/pulse-client.service
sudo systemctl daemon-reload && sudo systemctl restart pulse-client
```

### 🛡️ 回滚

旧的 `metrics.db` 在迁移时被自动备份为 `metrics.db.pre-restore-<时间戳>`，随时可以回滚：

```bash
# 独立二进制
sudo systemctl stop pulse-server
sudo cp /opt/pulse/data/metrics.db.pre-restore-* /opt/pulse/data/metrics.db
sudo systemctl start pulse-server

# Docker
docker compose stop
cp datatz/metrics.db.pre-restore-* datatz/metrics.db
docker compose up -d
```

在 `/admin` 登录正常、系统列表齐全、TCPing 图表渲染正常后，再删除这些 `.pre-restore-*` 文件即可。

### 📅 顺便：周期性备份

同一套脚本可以挂到 cron 做日常热备（零停机）：

```bash
# 每天 UTC 03:00 一次，环境变量传密码避免 ps 泄漏
0 3 * * * PASSWORD='YourAdminPW' /opt/pulse/scripts/backup.sh \
  --server http://127.0.0.1:8008 \
  --output /var/backups/pulse/pulse-$(date -u +\%Y\%m\%d).db
```

### ⚠️ 注意事项

- **备份文件等同于全部密钥**：里面包含所有系统的共享密钥和管理员密码哈希，和生产 DB 一样谨慎对待（文件权限、传输通道）。
- **不要同时运行两台服务端指向同一套客户端**——客户端会上报给最先通的那台，数据会分裂。迁移完成后及时下线旧端。
- **脚本参数全览**：`pulse-migrate --help`、`pulse-backup --help`、`pulse-restore --help`（或直接 `/opt/pulse/scripts/*.sh --help`）。

---

## ✨ 新特征

- 私有化模式
- Logo和名称自定义
- CPU类型检测
- 客户端一键部署

---

## 📄 License

[MIT](LICENSE)
