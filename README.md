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
  <a href="https://github.com/xhhcn/Pulse/releases"><img src="https://img.shields.io/github/v/release/xhhcn/Pulse?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/pulls/xhh1128/pulse?style=flat-square&color=blue" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/image-size/xhh1128/pulse/latest?style=flat-square&color=blue" alt="Docker Size"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/xhhcn/Pulse?style=flat-square&color=green" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Astro-4.0+-FF5D01?style=flat-square&logo=astro&logoColor=white" alt="Astro">
  <img src="https://img.shields.io/badge/Platform-amd64%20%7C%20arm64-lightgrey?style=flat-square" alt="Platform">
</p>

---

## 🚀 服务端安装

### 方式一：独立二进制部署（推荐新手和 VPS 用户）

#### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash
```

脚本会自动：
- ✅ 检测系统架构
- ✅ 下载对应的二进制文件
- ✅ 配置 systemd 服务
- ✅ 启动服务并设置开机自启

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

## ✨ 新特征

- 私有化模式
- Logo和名称自定义
- CPU类型检测
- 客户端一键部署

---

## 📄 License

[MIT](LICENSE)
