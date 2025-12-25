<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="Pulse Logo">
</p>

<h1 align="center">Pulse</h1>

<p align="center">
  <b>Lightweight Server Monitoring System</b><br>
  Real-time monitoring of CPU, memory, disk, network and other metrics
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

## 🚀 Server Installation

### Method 1: Standalone Binary Deployment (Recommended for VPS)

#### One-line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash
```

The script will automatically:
- ✅ Detect system architecture
- ✅ Download the appropriate binary
- ✅ Configure systemd service
- ✅ Start service and enable auto-start

#### Manual Installation

**Linux (amd64)**
```bash
# Download
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-amd64
chmod +x pulse-server-standalone-linux-amd64

# Run
./pulse-server-standalone-linux-amd64
```

**Linux (arm64)**
```bash
# Download
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-arm64
chmod +x pulse-server-standalone-linux-arm64

# Run
./pulse-server-standalone-linux-arm64
```

Access `http://YOUR_IP:8008` to view the monitoring dashboard

---

### Method 2: Docker Deployment (Recommended for Production)

[![Docker](https://img.shields.io/badge/Docker-xhh1128/pulse-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/xhh1128/pulse)

#### Docker Compose

```bash
mkdir pulse && cd pulse
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml
docker compose up -d
```

> **IPv6 Support**: If your server requires IPv6 support, please refer to the [Docker IPv6 Configuration](#docker-ipv6-configuration) section below.

#### Docker Run

```bash
docker run -d \
  --name pulse-monitor \
  -p 8008:8008 \
  -v $(pwd)/pulse-data:/app/data \
  --restart unless-stopped \
  xhh1128/pulse:latest
```

Access `http://YOUR_IP:8008` to view the monitoring dashboard

---

## 🌐 Docker IPv6 Configuration

Pulse supports IPv4/IPv6 dual-stack. If your server requires IPv6 support, please follow these steps:

### Prerequisites

1. **Ensure the host has IPv6 enabled**
   ```bash
   # Check if IPv6 is enabled
   ip -6 addr show
   
   # Check if IPv6 forwarding is enabled
   sysctl net.ipv6.conf.all.forwarding
   # If output is 0, enable it:
   sudo sysctl -w net.ipv6.conf.all.forwarding=1
   
   # Enable permanently (edit /etc/sysctl.conf)
   echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
   ```

2. **Configure Docker Daemon to enable IPv6**

   Edit or create `/etc/docker/daemon.json`:
   ```json
   {
     "ipv6": true,
     "fixed-cidr-v6": "fd00:dead:beef:c0::/80",
     "experimental": true,
     "ip6tables": true
   }
   ```
   
   > **Note**:
   > - `ipv6: true` - Globally enable Docker's IPv6 support (**required**)
   > - `fixed-cidr-v6` - IPv6 subnet range used by Docker (adjust according to your actual situation)
   > - `experimental: true` - Enable experimental features (required for some IPv6 features)
   > - `ip6tables: true` - Enable IPv6 iptables support (for network isolation and port mapping)
   
   Restart Docker service to apply the configuration:
   ```bash
   sudo systemctl restart docker
   ```

3. **Configure docker-compose.yaml to enable IPv6**

   Configure the network to enable IPv6 in `docker-compose.yaml`:
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

4. **Recreate containers**

   ```bash
   docker compose down
   docker compose up -d
   ```

5. **Verify IPv6 configuration**

   ```bash
   # Check container IPv6 address
   docker exec pulse-monitor ip -6 addr show
   
   # Test IPv6 connectivity (if container has ping6)
   docker exec pulse-monitor ping6 -c 2 2001:4860:4860::8888
   ```

---

## 📦 Client Installation

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

### Windows (Administrator PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "& { $env:AgentId='<ID>'; $env:ServerBase='<SERVER_URL>'; $env:Secret='<SECRET>'; irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex }"
```

| Parameter | Description |
|------|------|
| `<ID>` | Unique server identifier (set when adding system in admin panel) |
| `<SERVER_URL>` | Server URL, e.g., `http://your-server:8008` |
| `<SECRET>` | Authentication secret (auto-generated after adding system in admin panel, viewable in system details) |

> **Note**: The `--secret` parameter is optional. If the server system is configured with a secret, you must provide the correct secret to register successfully.

---

## ⚙️ Usage

1. Access `http://YOUR_IP:8008/admin` to enter the admin panel
2. Set admin password on first visit
3. Click **Add System** to add a server
4. After adding a system, a **Secret** (authentication key) will be automatically generated
5. Run the client installation command on the target machine, **must include the correct Secret**
6. Data is automatically reported and displayed in real-time

> **Tip**: In the admin panel's system list, click the copy button on the right side of the system to quickly copy the installation command with Secret.

---

## 📊 Monitoring Metrics

| Metric | Content |
|------|------|
| **CPU** | Usage, cores, model |
| **Memory** | Usage, total |
| **Disk** | Usage, total |
| **Network** | Upload/download speed, TCPing latency |
| **System** | Uptime, IP, location |

---

## ✨ New Features

- Privacy Mode
- Logo and Name Customization
- CPU Type Detection
- One-Click Client Deployment

---

## 📄 License

[MIT](LICENSE)

