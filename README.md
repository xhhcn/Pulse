<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="Pulse Logo">
</p>

<h1 align="center">Pulse</h1>

<p align="center">
  <b>轻量级服务器监控系统</b><br>
  实时监控 CPU、内存、磁盘、网络等指标
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

### Docker 部署（推荐）

```bash
mkdir pulse && cd pulse
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml
docker compose up -d
```

访问 `http://YOUR_IP:8008` 查看监控面板

> 💡 **修改端口**: `PORT=9000 docker compose up -d`

---

## 📦 客户端安装

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL>
```

### Windows (管理员 PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "& { $env:AgentId='<ID>'; $env:ServerBase='<SERVER_URL>'; irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex }"
```

| 参数 | 说明 |
|------|------|
| `<ID>` | 服务器唯一标识 |
| `<SERVER_URL>` | 服务端地址，如 `http://your-server:8008` |

---

## ⚙️ 使用方法

1. 访问 `http://YOUR_IP:8008/admin` 进入管理后台
2. 首次访问设置管理密码
3. 点击 **Add System** 添加服务器
4. 在目标机器上运行客户端安装命令
5. 数据自动上报，实时显示

---

## 📊 监控指标

| 指标 | 内容 |
|------|------|
| **CPU** | 使用率、核心数、型号 |
| **内存** | 使用率、总量 |
| **磁盘** | 使用率、总量 |
| **网络** | 上传/下载速率 |
| **系统** | 运行时间、IP、位置 |

---

## 🐳 Docker

```bash
docker pull xhh1128/pulse:latest
```

**支持架构**: `linux/amd64` `linux/arm64`

---

## 📄 License

[MIT](LICENSE)
