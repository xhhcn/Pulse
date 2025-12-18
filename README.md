# Pulse

轻量级服务器监控系统 - 实时监控 CPU、内存、磁盘、网络等指标

## 🚀 服务端安装

### Docker 部署（推荐）

```bash
# 创建 docker-compose.yaml
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml

# 启动服务
docker compose up -d
```

访问 `http://YOUR_IP:8008` 查看监控面板

> 💡 修改端口：`PORT=9000 docker compose up -d`

## 📦 客户端安装

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- --id <ID> --server <SERVER_URL>
```

### Windows (管理员 PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "& { $env:AgentId='<ID>'; $env:ServerBase='<SERVER_URL>'; irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex }"
```

**参数说明：**
- `<ID>` - 服务器唯一标识（在管理后台添加服务器时设置）
- `<SERVER_URL>` - 服务端地址，如 `http://your-server:8008`

## ⚙️ 使用方法

1. 访问管理后台：`http://YOUR_IP:8008/admin`
2. 首次访问设置管理密码
3. 点击 "Add System" 添加服务器
4. 在目标机器上运行客户端安装命令
5. 客户端会自动连接并上报数据

## 📊 监控指标

- CPU 使用率、核心数、型号
- 内存使用率、总量
- 磁盘使用率、总量
- 网络上传/下载速率
- 系统运行时间、IP 地址

## 🐳 Docker 镜像

```bash
docker pull xhh1128/pulse:latest
```

支持架构：`linux/amd64`, `linux/arm64`

## 📄 License

MIT
